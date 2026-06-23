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

if (navbar) {
  let isScrolled = false;
  window.addEventListener("scroll", () => {
    const scrolled = window.scrollY > 50;
    if (scrolled !== isScrolled) {
      isScrolled = scrolled;
      if (scrolled) {
        navbar.classList.add("scrolled");
      } else {
        navbar.classList.remove("scrolled");
      }
    }
  }, { passive: true });
}

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

    let mouseX = 0.5;
    let mouseY = 0.5;
    let ticking = false;

    window.addEventListener("mousemove", (e) => {
      mouseX = e.clientX / window.innerWidth;
      mouseY = e.clientY / window.innerHeight;

      if (!ticking) {
        requestAnimationFrame(() => {
          orbs.forEach((orb, index) => {
            const speed = (index + 1) * 20;
            const targetX = (mouseX - 0.5) * speed;
            const targetY = (mouseY - 0.5) * speed;
            quickX[index](targetX);
            quickY[index](targetY);
          });
          ticking = false;
        });
        ticking = true;
      }
    });
  } else {
    // Fallback if GSAP is not loaded
    let mouseX = 0.5;
    let mouseY = 0.5;
    let ticking = false;

    window.addEventListener("mousemove", (e) => {
      mouseX = e.clientX / window.innerWidth;
      mouseY = e.clientY / window.innerHeight;

      if (!ticking) {
        requestAnimationFrame(() => {
          orbs.forEach((orb, index) => {
            const speed = (index + 1) * 20;
            const x = (mouseX - 0.5) * speed;
            const y = (mouseY - 0.5) * speed;
            orb.style.transform = `translate(${x}px, ${y}px)`;
          });
          ticking = false;
        });
        ticking = true;
      }
    });
  }
});

// ===========================
// Feature Card Tilt Effect
// ===========================
document.querySelectorAll(".feature-card[data-tilt='true']").forEach((card) => {
  let rect = null;

  card.addEventListener("mouseenter", () => {
    rect = card.getBoundingClientRect();
  });

  card.addEventListener("mousemove", (e) => {
    if (!rect) rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    const rotateX = (y - centerY) / 20;
    const rotateY = (centerX - x) / 20;

    card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-8px)`;
  });

  card.addEventListener("mouseleave", () => {
    rect = null;
    card.style.transform =
      "perspective(1000px) rotateX(0) rotateY(0) translateY(0)";
  });
});

// ===========================
// Gradient Animation
// ===========================
// NOTE: Orb animation has been moved entirely to hardware-accelerated CSS keyframes in landing.css
// to prevent thread blocking and layout thrashing, resulting in smoother scrolling.

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

  // Optimized particle density to reduce connection calculations
  const getParticleCount = () => {
    return window.innerWidth < 768 ? 30 : 65;
  };

  let particleCount = getParticleCount();

  const colors = [
    "rgba(59, 130, 246, 0.4)", // var(--cg-accent) translucent
    "rgba(59, 130, 246, 0.3)",  // var(--cg-accent-hover) translucent
    "rgba(6, 182, 212, 0.3)",   // var(--cg-cyan) translucent
  ];

  let mouse = {
    x: null,
    y: null,
    radius: 130,
    radiusSq: 16900 // Pre-calculated radius squared (130 * 130)
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

      // Mouse attraction - Optimized distance check (avoids Math.sqrt if out of range)
      if (mouse.x !== null && mouse.y !== null) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const distSq = dx * dx + dy * dy;
        if (distSq < mouse.radiusSq) {
          const dist = Math.sqrt(distSq);
          if (dist > 0) {
            const force = (mouse.radius - dist) / mouse.radius;
            this.x += (dx / dist) * force * 0.25;
            this.y += (dy / dist) * force * 0.25;
          }
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
    const maxDistanceSq = 13225; // Pre-calculated maxDistance squared (115 * 115)
    ctx.lineWidth = 0.75;

    for (let i = 0; i < particles.length; i++) {
      const a = particles[i];

      // Connection to mouse - Optimized check
      if (mouse.x !== null && mouse.y !== null) {
        const dx = a.x - mouse.x;
        const dy = a.y - mouse.y;
        const distSq = dx * dx + dy * dy;
        if (distSq < mouse.radiusSq) {
          const dist = Math.sqrt(distSq);
          const opacity = (1 - dist / mouse.radius) * 0.15;
          ctx.strokeStyle = `rgba(59, 130, 246, ${opacity})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.stroke();
        }
      }

      // Connection to other particles - Optimized check (avoids Math.sqrt if out of range)
      for (let j = i + 1; j < particles.length; j++) {
        const b = particles[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const distSq = dx * dx + dy * dy;

        if (distSq < maxDistanceSq) {
          const dist = Math.sqrt(distSq);
          const opacity = (1 - dist / maxDistance) * 0.18;
          ctx.strokeStyle = `rgba(59, 130, 246, ${opacity})`;
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

  // Orb animation has been moved to hardware-accelerated CSS
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

    line.innerHTML = ` // security-audit-ignore
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
    { from: nodes.auth,to: nodes.api,  color: '#3b82f6' },
    { from: nodes.api, to: nodes.db,   color: '#3b82f6' },
    { from: nodes.gw,  to: nodes.auth, color: '#3b82f6' }
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
          <div class="font-extrabold uppercase text-blue-400 tracking-wide mb-1">Proxy Guard</div>
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
          <div class="font-extrabold uppercase text-blue-300 tracking-wide mb-1">Vault Core</div>
          <p class="text-slate-300">Encrypted relational database storing scanned telemetry, project access control scopes, and credentials vaulting.</p>
        </div>
      `,
      allowHTML: true,
      placement: "bottom",
      animation: "scale"
    });
  }
});

// ===========================
// Organization Workflow Section Interaction & Simulations
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const stepCards = document.querySelectorAll(".workflow-step-card");
  const previewPanes = document.querySelectorAll(".workflow-preview-pane");

  if (stepCards.length === 0 || previewPanes.length === 0) return;

  stepCards.forEach((card) => {
    const triggerHandler = () => {
      if (card.classList.contains("active")) return;

      // Reset active cards
      stepCards.forEach((c) => c.classList.remove("active"));
      card.classList.add("active");

      // Swap active preview panes
      const step = card.getAttribute("data-step");
      previewPanes.forEach((pane) => {
        if (pane.getAttribute("data-preview") === step) {
          pane.classList.add("active");
        } else {
          pane.classList.remove("active");
        }
      });
    };

    // Trigger on click
    card.addEventListener("click", triggerHandler);

    // Trigger on hover
    card.addEventListener("mouseenter", triggerHandler);
  });

  // -----------------------------
  // Step 1: Interactive Plan Switcher
  // -----------------------------
  const planPills = document.querySelectorAll("[data-plan-pill]");
  const mockPlanPrice = document.getElementById("mockPlanPrice");
  const mockPlanFeatures = document.getElementById("mockPlanFeatures");

  const plansData = {
    starter: {
      price: "$29/month",
      features: [
        "3 Team Seats",
        "Basic vulnerability scans",
        "Standard Email support"
      ]
    },
    pro: {
      price: "$49/month",
      features: [
        "5 Team Seats",
        "Standard vulnerability scans",
        "API & Webhook Access"
      ]
    },
    enterprise: {
      price: "Custom Pricing",
      features: [
        "Unlimited Seats",
        "Advanced deep scanning",
        "Dedicated 24/7 Security Engineer"
      ]
    }
  };

  if (planPills.length > 0 && mockPlanPrice && mockPlanFeatures) {
    planPills.forEach((pill) => {
      pill.addEventListener("click", () => {
        // Toggle active pill
        planPills.forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");

        const planKey = pill.getAttribute("data-plan-pill");
        const data = plansData[planKey];

        if (data) {
          // Update Price
          mockPlanPrice.textContent = data.price;

          // Rebuild Features Checklist
          mockPlanFeatures.innerHTML = "";
          data.features.forEach((feat, idx) => {
            const item = document.createElement("div");
            item.className = "mock-feature-item";
            item.style.opacity = "0";
            item.style.transform = "translateY(5px)";
            item.style.transition = "all 0.3s ease";
            // security-audit-ignore
            item.innerHTML = `
              <span class="chk-icon">✓</span>
              <span>${feat}</span>
            `;
            mockPlanFeatures.appendChild(item);

            // Stagger fade-in
            setTimeout(() => {
              item.style.opacity = "1";
              item.style.transform = "translateY(0)";
            }, idx * 80);
          });
        }
      });
    });
  }

  // -----------------------------
  // Step 2: 3D Credit Card Hover Tilt & Secure Payment Process
  // -----------------------------
  const card3dWrapper = document.querySelector(".mock-card-3d-wrapper");
  const creditCard = document.querySelector(".mock-credit-card");

  if (card3dWrapper && creditCard) {
    card3dWrapper.addEventListener("mousemove", (e) => {
      const rect = creditCard.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      const rotateX = (centerY - y) / 10;
      const rotateY = (x - centerX) / 10;

      creditCard.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateZ(10px)`;
    });

    card3dWrapper.addEventListener("mouseleave", () => {
      creditCard.style.transform = "perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0px)";
    });
  }

  const btnProcessPayment = document.getElementById("btnProcessPayment");
  const paymentStatusBadge = document.getElementById("paymentStatusBadge");
  const paymentStatusText = document.getElementById("paymentStatusText");

  if (btnProcessPayment && paymentStatusBadge && paymentStatusText) {
    let isProcessing = false;

    btnProcessPayment.addEventListener("click", () => {
      if (isProcessing) return;
      isProcessing = true;

      // Enter Loading State
      btnProcessPayment.disabled = true;
      const spinner = btnProcessPayment.querySelector(".btn-spinner");
      const btnText = btnProcessPayment.querySelector(".btn-text");

      if (spinner) spinner.classList.remove("hidden");
      if (btnText) btnText.textContent = "Processing Secure Payment...";

      if (paymentStatusBadge) {
        paymentStatusBadge.className = "status-badge-secure processing";
      }
      if (paymentStatusText) {
        paymentStatusText.textContent = "Authorizing Card...";
      }

      // Simulate Payment Delay
      setTimeout(() => {
        // Success Transition
        if (spinner) spinner.classList.add("hidden");
        if (btnText) btnText.textContent = "Payment Successful ✓";
        btnProcessPayment.classList.add("success");

        if (paymentStatusBadge) {
          paymentStatusBadge.className = "status-badge-secure";
        }
        if (paymentStatusText) {
          paymentStatusText.textContent = "Payment Securely Processed";
        }

        if (creditCard) {
          creditCard.classList.add("success-glow");
        }

        // Reset state after 4 seconds
        setTimeout(() => {
          if (btnText) btnText.textContent = "Process Secure Payment";
          btnProcessPayment.classList.remove("success");
          btnProcessPayment.disabled = false;
          if (creditCard) creditCard.classList.remove("success-glow");
          if (paymentStatusText) paymentStatusText.textContent = "Verified Checkout";
          isProcessing = false;
        }, 4000);

      }, 1800);
    });
  }

  // -----------------------------
  // Step 3: Typewriter DNS Verification Terminal
  // -----------------------------
  const btnRunAudit = document.getElementById("btnRunAudit");
  const terminalLinesContainer = document.getElementById("terminalLinesContainer");
  const mockTerminalRoles = document.getElementById("mockTerminalRoles");

  if (btnRunAudit && terminalLinesContainer) {
    const terminalLogs = [
      { type: "input", text: "dig TXT acme.com" },
      { type: "output", text: "; <<>> DiG 9.10.6 <<>> TXT acme.com" },
      { type: "output", text: "acme.com.   300   IN   TXT   \"cyberguard-verification=z78x9w...\"" },
      { type: "input", text: "./verify_domain.sh acme.com" },
      { type: "info", text: "[INFO] Checking DNS TXT record match..." },
      { type: "success", text: "[SUCCESS] DNS verification record match found!" },
      { type: "success", text: "[SUCCESS] Workspace 'acme' activated." }
    ];

    let typingTimer = null;

    btnRunAudit.addEventListener("click", () => {
      btnRunAudit.disabled = true;
      btnRunAudit.textContent = "Verifying...";
      if (mockTerminalRoles) mockTerminalRoles.classList.add("hidden");

      // Clear previous lines
      terminalLinesContainer.innerHTML = "";

      let logIdx = 0;

      function printNextLog() {
        if (logIdx >= terminalLogs.length) {
          // Done typing
          btnRunAudit.textContent = "DNS Verified ✓";
          if (mockTerminalRoles) {
            mockTerminalRoles.classList.remove("hidden");
            mockTerminalRoles.style.opacity = "0";
            setTimeout(() => {
              mockTerminalRoles.style.opacity = "1";
            }, 100);
          }

          // Reset option after 8 seconds
          setTimeout(() => {
            btnRunAudit.disabled = false;
            btnRunAudit.textContent = "Run DNS Verification";
          }, 8000);

          return;
        }

        const log = terminalLogs[logIdx];
        const line = document.createElement("div");
        line.className = "terminal-line";

        if (log.type === "input") {
          // security-audit-ignore
          line.innerHTML = `<span class="prompt">$</span> <span class="typed-text"></span><span class="terminal-cursor">|</span>`;
          terminalLinesContainer.appendChild(line);
          
          // Force layout reflow so the transition has something to transition from
          line.getBoundingClientRect();
          line.classList.add("reveal");

          // Typewriter effect
          const typedTextEl = line.querySelector(".typed-text");
          const cursorEl = line.querySelector(".terminal-cursor");
          let charIdx = 0;

          function typeChar() {
            if (charIdx < log.text.length) {
              if (typedTextEl) typedTextEl.textContent += log.text[charIdx];
              charIdx++;
              typingTimer = setTimeout(typeChar, 40);
            } else {
              // Finish line typing, remove cursor from this line, proceed to next
              if (cursorEl) cursorEl.remove();
              logIdx++;
              setTimeout(printNextLog, 400);
            }
          }
          typeChar();

        } else {
          // Outputs or status logs reveal instantly
          if (log.type === "output") {
            line.className = "terminal-line text-slate-500";
          } else if (log.type === "info") {
            line.className = "terminal-line text-blue-400 font-bold";
          } else if (log.type === "success") {
            line.className = "terminal-line text-emerald-400 font-bold";
          }
          line.textContent = log.text;
          terminalLinesContainer.appendChild(line);

          // Force reflow and reveal
          line.getBoundingClientRect();
          line.classList.add("reveal");

          // Autoscroll terminal
          terminalLinesContainer.scrollTop = terminalLinesContainer.scrollHeight;

          logIdx++;
          setTimeout(printNextLog, 600);
        }
      }

      printNextLog();
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
