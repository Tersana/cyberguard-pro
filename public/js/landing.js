// ===========================
// Mobile Menu Toggle
// ===========================
const mobileMenuBtn = document.getElementById("mobileMenuBtn");
const mobileMenu = document.getElementById("mobileMenu");

mobileMenuBtn?.addEventListener("click", () => {
  mobileMenu.classList.toggle("active");
});

// Close mobile menu when clicking on a link
document.querySelectorAll(".mobile-link").forEach((link) => {
  link.addEventListener("click", () => {
    mobileMenu.classList.remove("active");
  });
});

// ===========================
// Account Dropdown Toggle
// ===========================
document.addEventListener('DOMContentLoaded', () => {
  const dropdownToggle = document.querySelector('.dropdown-toggle');
  const dropdown = document.querySelector('.dropdown');
  
  if (dropdownToggle && dropdown) {
    dropdownToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('active');
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      if (!dropdown.contains(e.target)) {
        dropdown.classList.remove('active');
      }
    });
  }
});

// ===========================
// Navbar Scroll Effect
// ===========================
const navbar = document.querySelector(".navbar");

window.addEventListener("scroll", () => {
  if (window.scrollY > 50) {
    navbar.classList.add("scrolled");
  } else {
    navbar.classList.remove("scrolled");
  }
});

// ===========================
// Smooth Scroll for Anchor Links
// ===========================
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener("click", function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute("href"));
    if (target) {
      const offsetTop = target.offsetTop - 80;
      window.scrollTo({
        top: offsetTop,
        behavior: "smooth",
      });
    }
  });
});

// ===========================
// Scroll Animation Observer
// ===========================
const animateOnScrollOptions = {
  threshold: 0.1,
  rootMargin: "0px 0px -100px 0px",
};

const animateOnScroll = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      const delay = (parseInt(entry.target.getAttribute("data-delay")) || 0) / 1000;
      
      if (typeof gsap !== "undefined" && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        // High-end GSAP entrance animation
        gsap.fromTo(entry.target, 
          { opacity: 0, y: 30 },
          { opacity: 1, y: 0, duration: 0.8, delay: delay, ease: "power2.out" }
        );
      } else {
        // Fallback for CSS/Reduced motion
        entry.target.classList.add("aos-animate");
      }
      animateOnScroll.unobserve(entry.target);
    }
  });
}, animateOnScrollOptions);

// Observe all elements with data-aos attribute
document.querySelectorAll("[data-aos]").forEach((element) => {
  animateOnScroll.observe(element);
});

// ===========================
// Parallax Effect for Hero Orbs
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const orbs = document.querySelectorAll(".gradient-orb");
  if (orbs.length === 0) return;

  if (typeof gsap !== "undefined" && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const quickX = [];
    const quickY = [];

    orbs.forEach((orb) => {
      quickX.push(gsap.quickTo(orb, "x", { duration: 0.8, ease: "power2.out" }));
      quickY.push(gsap.quickTo(orb, "y", { duration: 0.8, ease: "power2.out" }));
    });

    window.addEventListener("mousemove", (e) => {
      const mouseX = e.clientX / window.innerWidth;
      const mouseY = e.clientY / window.innerHeight;

      orbs.forEach((orb, index) => {
        const speed = (index + 1) * 20;
        const targetX = (mouseX - 0.5) * speed;
        const targetY = (mouseY - 0.5) * speed;
        quickX[index](targetX);
        quickY[index](targetY);
      });
    });
  } else {
    // Fallback if GSAP is not loaded
    window.addEventListener("mousemove", (e) => {
      const mouseX = e.clientX / window.innerWidth;
      const mouseY = e.clientY / window.innerHeight;

      orbs.forEach((orb, index) => {
        const speed = (index + 1) * 20;
        const x = (mouseX - 0.5) * speed;
        const y = (mouseY - 0.5) * speed;
        orb.style.transform = `translate(${x}px, ${y}px)`;
      });
    });
  }
});

// ===========================
// Feature Card Tilt Effect
// ===========================
document.querySelectorAll(".feature-card").forEach((card) => {
  card.addEventListener("mousemove", (e) => {
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    const rotateX = (y - centerY) / 20;
    const rotateY = (centerX - x) / 20;

    card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-8px)`;
  });

  card.addEventListener("mouseleave", () => {
    card.style.transform =
      "perspective(1000px) rotateX(0) rotateY(0) translateY(0)";
  });
});

// ===========================
// Gradient Animation
// ===========================
const gradientOrbs = document.querySelectorAll(".gradient-orb");
let orbAnimationFrame;

function animateOrbs() {
  const time = Date.now() * 0.001;

  gradientOrbs.forEach((orb, index) => {
    const speed = 0.5 + index * 0.2;
    const x = Math.sin(time * speed) * 50;
    const y = Math.cos(time * speed) * 50;
    const scale = 1 + Math.sin(time * speed * 2) * 0.1;

    orb.style.transform = `translate(${x}px, ${y}px) scale(${scale})`;
  });

  orbAnimationFrame = requestAnimationFrame(animateOrbs);
}

// Start orb animation
animateOrbs();

// ===========================
// Tool Item Stagger Animation
// ===========================
document
  .querySelectorAll(".tool-category")
  .forEach((category, categoryIndex) => {
    const toolItems = category.querySelectorAll(".tool-item");

    const toolObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            toolItems.forEach((item, index) => {
              setTimeout(() => {
                item.style.opacity = "1";
                item.style.transform = "translateX(0)";
              }, index * 100);
            });
            toolObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.3 }
    );

    // Set initial state
    toolItems.forEach((item) => {
      item.style.opacity = "0";
      item.style.transform = "translateX(-20px)";
      item.style.transition = "all 0.4s ease-out";
    });

    toolObserver.observe(category);
  });


// ===========================
// Global Particle Network Background
// ===========================
(function () {
  const canvas = document.getElementById("global-particle-canvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  let animationId;
  let particles = [];
  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  // Responsive particle density
  const getParticleCount = () => {
    return window.innerWidth < 768 ? 45 : 115;
  };

  let particleCount = getParticleCount();

  const colors = [
    "rgba(167, 139, 250, 0.4)", // var(--cg-accent) translucent
    "rgba(139, 92, 246, 0.3)",  // var(--cg-accent-hover) translucent
    "rgba(6, 182, 212, 0.3)",   // var(--cg-cyan) translucent
  ];

  let mouse = {
    x: null,
    y: null,
    radius: 130
  };

  window.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  window.addEventListener("mouseleave", () => {
    mouse.x = null;
    mouse.y = null;
  });

  class GlobalParticle {
    constructor() {
      this.reset(true);
    }

    reset(init = false) {
      this.x = Math.random() * width;
      this.y = init ? Math.random() * height : height + 10;
      this.size = Math.random() * 2 + 0.8;
      this.vx = (Math.random() - 0.5) * 0.35;
      this.vy = (Math.random() - 0.5) * 0.35;
      this.color = colors[Math.floor(Math.random() * colors.length)];
      this.alpha = Math.random() * 0.4 + 0.3;
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      // Wrap around edges
      if (this.x < -10) this.x = width + 10;
      if (this.x > width + 10) this.x = -10;
      if (this.y < -10) this.y = height + 10;
      if (this.y > height + 10) this.y = -10;

      // Mouse attraction
      if (mouse.x !== null && mouse.y !== null) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          this.x += (dx / dist) * force * 0.25;
          this.y += (dy / dist) * force * 0.25;
        }
      }
    }

    draw() {
      ctx.fillStyle = this.color;
      ctx.globalAlpha = this.alpha;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function initParticles() {
    particles = [];
    particleCount = getParticleCount();
    for (let i = 0; i < particleCount; i++) {
      particles.push(new GlobalParticle());
    }
  }

  function drawConnections() {
    const maxDistance = 115;
    ctx.lineWidth = 0.75;

    for (let i = 0; i < particles.length; i++) {
      const a = particles[i];

      // Connection to mouse
      if (mouse.x !== null && mouse.y !== null) {
        const dx = a.x - mouse.x;
        const dy = a.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const opacity = (1 - dist / mouse.radius) * 0.15;
          ctx.strokeStyle = `rgba(167, 139, 250, ${opacity})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.stroke();
        }
      }

      // Connection to other particles
      for (let j = i + 1; j < particles.length; j++) {
        const b = particles[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < maxDistance) {
          const opacity = (1 - dist / maxDistance) * 0.18;
          ctx.strokeStyle = `rgba(167, 139, 250, ${opacity})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);
    ctx.globalAlpha = 1;

    particles.forEach((p) => {
      p.update();
      p.draw();
    });

    drawConnections();

    animationId = requestAnimationFrame(animate);
  }

  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)");

  function handleMotionPreference(mediaQuery) {
    if (mediaQuery.matches) {
      if (animationId) {
        cancelAnimationFrame(animationId);
      }
      ctx.clearRect(0, 0, width, height);
      particles.forEach((p) => p.draw());
      drawConnections();
    } else {
      if (animationId) cancelAnimationFrame(animationId);
      animate();
    }
  }

  // Initial call
  initParticles();
  handleMotionPreference(prefersReduced);
  prefersReduced.addEventListener("change", handleMotionPreference);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    initParticles();
    if (prefersReduced.matches) {
      ctx.clearRect(0, 0, width, height);
      particles.forEach((p) => p.draw());
      drawConnections();
    }
  });
})();

// ===========================
// Headline Typewriter Effect
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const typewriterSpan = document.getElementById("typewriter");
  if (!typewriterSpan) return;

  const words = ["Cybersecurity", "Threat Detection", "Vulnerability Scan", "Network Security"];

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    typewriterSpan.textContent = words[0];
    return;
  }

  if (typeof gsap !== "undefined") {
    const tl = gsap.timeline({ repeat: -1 });

    words.forEach((word) => {
      const obj = { length: 0 };
      
      // Type write word
      tl.to(obj, {
        length: word.length,
        duration: word.length * 0.08 + 0.3,
        ease: "none",
        onUpdate: () => {
          typewriterSpan.textContent = word.substring(0, Math.ceil(obj.length));
        }
      })
      // Pause at full word
      .to({}, { duration: 2 })
      // Delete word
      .to(obj, {
        length: 0,
        duration: word.length * 0.04 + 0.15,
        ease: "none",
        onUpdate: () => {
          typewriterSpan.textContent = word.substring(0, Math.ceil(obj.length));
        }
      })
      // Pause after deletion
      .to({}, { duration: 0.5 });
    });
  } else {
    // Fallback if GSAP is not loaded
    let wordIndex = 0;
    let charIndex = words[0].length;
    let isDeleting = true;
    let typingSpeed = 150;

    function type() {
      const currentWord = words[wordIndex];
      
      if (isDeleting) {
        typewriterSpan.textContent = currentWord.substring(0, charIndex - 1);
        charIndex--;
        typingSpeed = 60;
      } else {
        typewriterSpan.textContent = currentWord.substring(0, charIndex + 1);
        charIndex++;
        typingSpeed = 130;
      }

      if (!isDeleting && charIndex === currentWord.length) {
        typingSpeed = 2000;
        isDeleting = true;
      } else if (isDeleting && charIndex === 0) {
        isDeleting = false;
        wordIndex = (wordIndex + 1) % words.length;
        typingSpeed = 500;
      }

      setTimeout(type, typingSpeed);
    }
    setTimeout(type, 1500);
  }
});




// ===========================
// Preload Animation
// ===========================
window.addEventListener("load", () => {
  document.body.style.opacity = "0";
  setTimeout(() => {
    document.body.style.transition = "opacity 0.5s ease";
    document.body.style.opacity = "1";
  }, 100);
});

// ===========================
// Performance Optimization
// ===========================
// Disable animations on low-end devices
if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
  document.querySelectorAll("[data-aos]").forEach((element) => {
    element.classList.add("aos-animate");
  });

  // Stop orb animation
  if (orbAnimationFrame) {
    cancelAnimationFrame(orbAnimationFrame);
  }
}

// ===========================
// Easter Egg: Konami Code
// ===========================
let konamiCode = [];
const konamiPattern = [
  "ArrowUp",
  "ArrowUp",
  "ArrowDown",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "ArrowLeft",
  "ArrowRight",
  "b",
  "a",
];

document.addEventListener("keydown", (e) => {
  konamiCode.push(e.key);
  konamiCode = konamiCode.slice(-konamiPattern.length);

  if (konamiCode.join(",") === konamiPattern.join(",")) {
    document.body.style.animation = "rainbow 2s linear infinite";
    setTimeout(() => {
      document.body.style.animation = "";
    }, 5000);
  }
});

// Rainbow animation for easter egg
const style = document.createElement("style");
style.textContent = `
    @keyframes rainbow {
        0% { filter: hue-rotate(0deg); }
        100% { filter: hue-rotate(360deg); }
    }
`;
document.head.appendChild(style);

// ===========================
// Hero Animated Terminal
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const terminalBody = document.getElementById("heroTerminalBody");
  if (!terminalBody) return;

  const logs = [
    { type: 'scan', text: 'Initializing recon on testsite.com...' },
    { type: 'info', text: 'Auditing OWASP Top 10 vulnerabilities...' },
    { type: 'scan', text: 'Testing SQL injection vulnerability vectors...' },
    { type: 'ok', text: 'SQLi vectors: Sanitized / Secure' },
    { type: 'scan', text: 'Checking for cross-site scripting (XSS)...' },
    { type: 'blocked', text: 'VULN FOUND: XSS payload accepted on /query' },
    { type: 'info', text: 'Severity: HIGH | CVE-2026-XSS-RECON' },
    { type: 'scan', text: 'Analyzing file integrity signatures...' },
    { type: 'ok', text: 'Core binaries untampered' },
    { type: 'scan', text: 'Scanning for exposed directories...' },
    { type: 'blocked', text: 'VULN FOUND: Exposed .env file on root' },
    { type: 'info', text: 'Severity: CRITICAL | Credentials leaked' },
    { type: 'scan', text: 'Checking endpoint authentication...' },
    { type: 'ok', text: 'Access control: Strict JWT verified' },
    { type: 'blocked', text: 'VULN FOUND: Outdated Apache (CVE-2021-41773)' },
    { type: 'info', text: 'Severity: MEDIUM | Path Traversal possible' },
    { type: 'info', text: 'Scan complete. 3 Vulnerabilities identified.' }
  ];

  let logIndex = 0;

  function appendLog() {
    if (!document.getElementById("heroTerminalBody")) return;
    
    if (logIndex >= logs.length) {
      setTimeout(() => {
        const body = document.getElementById("heroTerminalBody");
        if (body) {
          body.innerHTML = '';
          logIndex = 0;
          appendLog();
        }
      }, 5000);
      return;
    }

    const log = logs[logIndex];
    const line = document.createElement("div");
    line.className = "terminal-line";

    let tagClass = '';
    let tagText = '';

    if (log.type === 'scan') {
      tagClass = 'scan';
      tagText = 'SCAN';
    } else if (log.type === 'info') {
      tagClass = 'info';
      tagText = 'INFO';
    } else if (log.type === 'ok') {
      tagClass = 'ok';
      tagText = ' OK ';
    } else if (log.type === 'blocked') {
      tagClass = 'blocked';
      tagText = 'VULN';
    }

    line.innerHTML = `
      <span class="term-tag ${tagClass}">${tagText}</span>
      <span class="term-text">${log.text}</span>
    `;

    terminalBody.appendChild(line);
    
    // Auto-scroll to bottom
    terminalBody.scrollTop = terminalBody.scrollHeight;

    // Keep only last 6 lines to fit the height of the terminal
    if (terminalBody.children.length > 6) {
      terminalBody.removeChild(terminalBody.firstChild);
    }

    logIndex++;
    
    const delay = Math.random() * 600 + 400;
    setTimeout(appendLog, delay);
  }

  appendLog();
});

// ===========================
// Zero-Trust Network Graph Animation
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const canvas = document.getElementById("zeroTrustCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  
  canvas.width = 400;
  canvas.height = 400;

  const nodes = {
    api:  { x: 200, y: 60 },
    gw:   { x: 80,  y: 200 },
    auth: { x: 320, y: 200 },
    db:   { x: 200, y: 340 }
  };

  const connections = [
    { from: nodes.api, to: nodes.gw,   color: '#3b82f6' },
    { from: nodes.gw,  to: nodes.db,   color: '#a855f7' },
    { from: nodes.db,  to: nodes.auth, color: '#10b981' },
    { from: nodes.auth,to: nodes.api,  color: '#8b5cf6' },
    { from: nodes.api, to: nodes.db,   color: '#6366f1' },
    { from: nodes.gw,  to: nodes.auth, color: '#6366f1' }
  ];

  class Comet {
    constructor(connection) {
      this.from = connection.from;
      this.to = connection.to;
      this.color = connection.color;
      this.progress = Math.random();
      this.speed = Math.random() * 0.005 + 0.003;
      this.size = Math.random() * 2 + 1.5;
    }

    update() {
      this.progress += this.speed;
      if (this.progress >= 1) {
        this.progress = 0;
        if (Math.random() > 0.5) {
          const temp = this.from;
          this.from = this.to;
          this.to = temp;
        }
      }
    }

    draw() {
      const x = this.from.x + (this.to.x - this.from.x) * this.progress;
      const y = this.from.y + (this.to.y - this.from.y) * this.progress;

      ctx.beginPath();
      ctx.arc(x, y, this.size, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.shadowBlur = 8;
      ctx.shadowColor = this.color;
      ctx.fill();

      ctx.shadowBlur = 0;
      for (let i = 1; i <= 5; i++) {
        const trailProgress = this.progress - (i * 0.015);
        if (trailProgress >= 0 && trailProgress <= 1) {
          const tx = this.from.x + (this.to.x - this.from.x) * trailProgress;
          const ty = this.from.y + (this.to.y - this.from.y) * trailProgress;
          ctx.beginPath();
          ctx.arc(tx, ty, this.size * (1 - i * 0.16), 0, Math.PI * 2);
          ctx.fillStyle = this.color;
          ctx.fill();
        }
      }
    }
  }

  const comets = connections.map(conn => new Comet(conn));

  function animateGraph() {
    if (!document.getElementById("zeroTrustCanvas")) return;
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    comets.forEach(comet => {
      comet.update();
      comet.draw();
    });

    requestAnimationFrame(animateGraph);
  }

  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    animateGraph();
  }
});

// ===========================
// Interactive Zero-Trust Node Map Tooltips (Tippy.js)
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  if (typeof tippy !== "undefined") {
    // API Gateway tooltip
    tippy(".node-api", {
      theme: "translucent",
      content: `
        <div class="p-2 max-w-[220px] text-xs leading-relaxed font-sans text-left">
          <div class="font-extrabold uppercase text-blue-400 tracking-wide mb-1">API Gateway</div>
          <p class="text-slate-300">Central entry point for all security telemetries. Conducts rate-limiting, CORS validation, and sanitizes payload streams.</p>
        </div>
      `,
      allowHTML: true,
      placement: "top",
      animation: "scale"
    });

    // Proxy Guard tooltip
    tippy(".node-gw", {
      theme: "translucent",
      content: `
        <div class="p-2 max-w-[220px] text-xs leading-relaxed font-sans text-left">
          <div class="font-extrabold uppercase text-purple-400 tracking-wide mb-1">Proxy Guard</div>
          <p class="text-slate-300">Monitors outbound reconnaissance queries. Isolates backend engines and proxies OWASP ZAP endpoints to prevent raw exposure.</p>
        </div>
      `,
      allowHTML: true,
      placement: "left",
      animation: "scale"
    });

    // Auth Core tooltip
    tippy(".node-auth", {
      theme: "translucent",
      content: `
        <div class="p-2 max-w-[220px] text-xs leading-relaxed font-sans text-left">
          <div class="font-extrabold uppercase text-emerald-400 tracking-wide mb-1">Auth Core</div>
          <p class="text-slate-300">Manages secure session states, 2FA tokens, and generates cryptographically signed JWT keys for strict request verification.</p>
        </div>
      `,
      allowHTML: true,
      placement: "right",
      animation: "scale"
    });

    // Vault Core tooltip
    tippy(".node-db", {
      theme: "translucent",
      content: `
        <div class="p-2 max-w-[220px] text-xs leading-relaxed font-sans text-left">
          <div class="font-extrabold uppercase text-purple-300 tracking-wide mb-1">Vault Core</div>
          <p class="text-slate-300">Encrypted relational database storing scanned telemetry, project access control scopes, and credentials vaulting.</p>
        </div>
      `,
      allowHTML: true,
      placement: "bottom",
      animation: "scale"
    });
  }
});



console.log(
  "%c CyberGuard",
  "font-size: 24px; font-weight: bold; color: #667eea;"
);
console.log(
  "%cWelcome to CyberGuard! Your comprehensive cybersecurity toolkit.",
  "font-size: 14px; color: #64748b;"
);