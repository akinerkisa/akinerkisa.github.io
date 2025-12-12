const view = document.getElementById('content');
const clock = document.getElementById('wmClock');

let siteData = null;

const DEFAULT_DATA = {
  vulnerabilities: { recent: [], all: [] },
  publishings: { recent: [], all: [] },
  projects: { recent: [], all: [] }
};

function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function sanitizeURL(str) {
  if (typeof str !== 'string') return '#';
  if (str === '#') return '#';
  return str.replace(/[<>]/g, ''); 
}

function isValidURL(string) {
  try {
    const url = new URL(string);
    return ['http:', 'https:'].includes(url.protocol);
  } catch (_) {
    return false;
  }
}

function setSafeAttribute(element, attribute, value) {
  if (typeof value !== 'string') return;
  const allowedAttributes = ['href', 'target', 'rel', 'class', 'id'];
  if (!allowedAttributes.includes(attribute)) return;
  
  if (attribute === 'href') {
    if (value !== '#' && !isValidURL(value)) {
      value = '#';
    }
    element.setAttribute(attribute, sanitizeURL(value));
  } else {
    element.setAttribute(attribute, sanitizeHTML(value));
  }
}

function clearElement(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

const routes = {
  '/': 'tpl-home',
  '/vulnerabilities': 'tpl-vulnerabilities',
  '/projects': 'tpl-projects',
  '/notes': 'tpl-notes',
};

function parseMarkdownData(markdownText) {
  const lines = markdownText.split('\n');
  const data = {
    vulnerabilities: { recent: [], all: [] },
    publishings: { recent: [], all: [] },
    projects: { recent: [], all: [] }
  };
  
  let currentSection = null;
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    if (trimmed === '## Vulnerabilities') {
      currentSection = 'vulnerabilities';
    } else if (trimmed === '## Publishings') {
      currentSection = 'publishings';
    } else if (trimmed === '## Projects') {
      currentSection = 'projects';
    } else if (trimmed.startsWith('- ') && currentSection) {
      const content = trimmed.substring(2);
      const item = parseDataItem(content, currentSection);
      if (item) {
        data[currentSection].all.push(item);
      }
    }
  }
  
  data.vulnerabilities.recent = data.vulnerabilities.all.slice(0, 3);
  data.publishings.recent = data.publishings.all.slice(0, 3);
  data.projects.recent = data.projects.all.slice(0, 3);
  
  data.vulnerabilities.stats = {
    total: data.vulnerabilities.all.length,
    cves: data.vulnerabilities.all.filter(v => v.title && v.title.includes('CVE-')).length,
    exploits: data.vulnerabilities.all.filter(v => v.title && v.title.includes('Exploit-DB')).length
  };
  
  return data;
}

function parseDataItem(content, section) {
  if (!content || typeof content !== 'string') return null;
  
  let item = null;
  
        if (section === 'vulnerabilities') {
          // Format: "2024-01-01: CVE-2024-1234: XXX Vulnerability on YYYY | https://cve.mitre.org/xxx"
          const match = content.match(/^(\d{4}-\d{2}-\d{2}):\s*(.+?)(?:\s*\|\s*(.+))?$/);
          if (match) {
            item = {
              date: match[1],
              title: match[2].trim(),
              url: match[3] ? match[3].trim() : '#'
            };
          }
        } else if (section === 'publishings') {
          // Format: "2024-01-01: web vulnerabilities: sql injection, rce etc. | https://medium.com/xxx"
          const match = content.match(/^(\d{4}-\d{2}-\d{2}):\s*(.+?)(?:\s*\|\s*(.+))?$/);
          if (match) {
            item = {
              date: match[1],
              title: match[2].trim(),
              url: match[3] ? match[3].trim() : '#'
            };
          }
        } else if (section === 'projects') {
          // Format: "websec-scanner: web vulnerability scanner | python, web, scanner | https://github.com/xxx"
          const match = content.match(/^([^:]+):\s*([^|]+?)(?:\s*\|\s*([^|]+?)(?:\s*\|\s*(.+))?)?$/);
          if (match) {
            const technologies = match[3] ? match[3].split(',').map(tech => tech.trim()) : [];
            item = {
              name: match[1],
              description: match[2].trim(),
              url: match[4] ? match[4].trim() : '#',
              technologies: technologies
            };
          }
        }
  
  if (!item || typeof item !== 'object') return null;
  
  const sanitized = {};
  
  if (item.date && typeof item.date === 'string') {
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (dateRegex.test(item.date)) {
      sanitized.date = item.date;
    }
  }
  
  if (item.title && typeof item.title === 'string') {
    const cleanTitle = item.title.substring(0, 200).trim();
    if (cleanTitle.length > 0) {
      sanitized.title = cleanTitle;
    }
  }
  
  if (item.url && typeof item.url === 'string') {
    if (isValidURL(item.url) || item.url === '#') {
      sanitized.url = item.url;
    } else {
      sanitized.url = '#';
    }
  } else {
    sanitized.url = '#';
  }
  
  if (section === 'projects') {
    if (item.name && typeof item.name === 'string') {
      const cleanName = item.name.substring(0, 50).trim();
      if (cleanName.length > 0) {
        sanitized.name = cleanName;
      }
    }
    
    if (item.description && typeof item.description === 'string') {
      const cleanDesc = item.description.substring(0, 300).trim();
      if (cleanDesc.length > 0) {
        sanitized.description = cleanDesc;
      }
    }
    
    if (item.technologies && Array.isArray(item.technologies)) {
      sanitized.technologies = item.technologies
        .filter(tech => typeof tech === 'string' && tech.trim().length > 0)
        .map(tech => tech.trim().substring(0, 20))
        .slice(0, 10);
    }
  }
  
  return Object.keys(sanitized).length > 0 ? sanitized : null;
}

async function loadSiteData() {
  if (siteData) return siteData;
  
  try {
    const response = await fetch('data.md');
    if (!response.ok) {
      throw new Error(`Failed to fetch data.md: ${response.status}`);
    }
    const markdownText = await response.text();
    siteData = parseMarkdownData(markdownText);
    return siteData;
  } catch (error) {
    console.error('Error loading site data:', error);
    return DEFAULT_DATA;
  }
}

function createSafeElement(tag, attributes = {}, textContent = '') {
  const element = document.createElement(tag);
  
  Object.entries(attributes).forEach(([key, value]) => {
    setSafeAttribute(element, key, value);
  });
  
  if (textContent) {
    element.textContent = textContent;
  }
  
  return element;
}

function renderList(items, type, isRecent = false) {
  const data = isRecent ? items.slice(0, 3) : items;
  const fragment = document.createDocumentFragment();
  
  data.forEach(item => {
    const li = createSafeElement('li');
    
    if (type === 'projects') {
      li.style.cursor = 'pointer';
      li.addEventListener('click', () => {
        if (item.url && item.url !== '#') {
          window.location.href = item.url;
        }
      });
      
      const itemHead = createSafeElement('div', { class: 'item-head' });
      const projectName = createSafeElement('span', { class: 'project-name' }, item.name || '');
      itemHead.appendChild(projectName);
      
      const itemDesc = createSafeElement('div', { class: 'item-desc' }, item.description || '');
      
      li.appendChild(itemHead);
      li.appendChild(itemDesc);
      
      if (!isRecent && item.technologies && Array.isArray(item.technologies)) {
        const tagsDiv = createSafeElement('div', { class: 'tags' });
        
        item.technologies.forEach(tech => {
          const tag = createSafeElement('span', { class: 'tag' }, tech || '');
          tagsDiv.appendChild(tag);
        });
        
        li.appendChild(tagsDiv);
      }
    } else {
      const dateSpan = createSafeElement('span', { class: 'note-date' }, item.date || '');
      const titleLink = createSafeElement('a', { 
        href: item.url || '#', 
        class: 'note-title' 
      }, item.title || '');
      
      li.appendChild(dateSpan);
      li.appendChild(titleLink);
    }
    
    fragment.appendChild(li);
  });
  
  return fragment;
}

function currentRoute() {
  const hash = location.hash.replace(/^#/, '');
  return hash || '/';
}

function setActive(route) {
  document.querySelectorAll('.wm-workspaces a').forEach(a => {
    const href = a.getAttribute('href').replace(/^#/, '');
    const isActive = href === route;
    a.classList.toggle('active', isActive);
    if (isActive) {
      a.setAttribute('aria-current', 'page');
    } else {
      a.removeAttribute('aria-current');
    }
  });
}


function updateClock() {
  if (!clock) return;
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  clock.textContent = `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function scrollToTop() {
  if (window.scrollY > 0) {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

async function render() {
  const route = currentRoute();
  const id = routes[route] || routes['/'];
  const tpl = document.getElementById(id);
  setActive(route);
  
  if (!tpl) {
    view.textContent = 'Not Found.';
    return;
  }
  
  view.classList.remove('show');
  
  try {
    const data = await loadSiteData();
    
    clearElement(view);
    const templateContent = tpl.content.cloneNode(true);
    
    if (route === '/') {
      const vulnNotes = templateContent.querySelector('.vuln-recent .notes');
      if (vulnNotes) {
        clearElement(vulnNotes);
        vulnNotes.appendChild(renderList(data.vulnerabilities.recent, 'vulnerabilities', true));
      }
      
      const pubNotes = templateContent.querySelector('.publishings-content .notes');
      if (pubNotes) {
        clearElement(pubNotes);
        pubNotes.appendChild(renderList(data.publishings.recent, 'publishings', true));
      }
      
      const projNotes = templateContent.querySelector('.projects-list-home');
      if (projNotes) {
        clearElement(projNotes);
        projNotes.appendChild(renderList(data.projects.recent, 'projects', true));
      }
      
    } else if (route === '/vulnerabilities') {
      const totalEl = templateContent.querySelector('#total-vulns');
      const cveEl = templateContent.querySelector('#cve-count');
      const exploitEl = templateContent.querySelector('#exploit-count');
      
      if (totalEl && data.vulnerabilities.stats) {
        totalEl.textContent = data.vulnerabilities.stats.total;
      }
      if (cveEl && data.vulnerabilities.stats) {
        cveEl.textContent = data.vulnerabilities.stats.cves;
      }
      if (exploitEl && data.vulnerabilities.stats) {
        exploitEl.textContent = data.vulnerabilities.stats.exploits;
      }
      
      const vulnNotes = templateContent.querySelector('.notes');
      if (vulnNotes) {
        clearElement(vulnNotes);
        vulnNotes.appendChild(renderList(data.vulnerabilities.all, 'vulnerabilities'));
      }
      
    } else if (route === '/notes') {
      const pubNotes = templateContent.querySelector('.notes');
      if (pubNotes) {
        clearElement(pubNotes);
        pubNotes.appendChild(renderList(data.publishings.all, 'publishings'));
      }
      
    } else if (route === '/projects') {
      const projNotes = templateContent.querySelector('.projects-list');
      if (projNotes) {
        clearElement(projNotes);
        projNotes.appendChild(renderList(data.projects.all, 'projects'));
      }
    }
    
    view.appendChild(templateContent);
    view.classList.add('show');
    scrollToTop();
    
  } catch (error) {
    console.error('Error rendering page:', error);
    clearElement(view);
    view.appendChild(tpl.content.cloneNode(true));
    view.classList.add('show');
  }
}

window.addEventListener('hashchange', render);
window.addEventListener('DOMContentLoaded', () => {
  render();
  updateClock();
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();
});
