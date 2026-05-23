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
  entries.forEach((entry, index) => {
    if (entry.isIntersecting) {
      const delay = entry.target.getAttribute("data-delay") || 0;
      setTimeout(() => {
        entry.target.classList.add("aos-animate");
      }, delay);
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
window.addEventListener("mousemove", (e) => {
  const orbs = document.querySelectorAll(".gradient-orb");
  const mouseX = e.clientX / window.innerWidth;
  const mouseY = e.clientY / window.innerHeight;

  orbs.forEach((orb, index) => {
    const speed = (index + 1) * 20;
    const x = (mouseX - 0.5) * speed;
    const y = (mouseY - 0.5) * speed;
    orb.style.transform = `translate(${x}px, ${y}px)`;
  });
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
// Security Shield Rotation
// ===========================
const securityShield = document.querySelector(".security-shield");
if (securityShield) {
  let rotation = 0;
  setInterval(() => {
    rotation += 0.5;
    securityShield.style.transform = `rotate(${rotation}deg)`;
  }, 50);
}

// ===========================
// Hero Particle Canvas Background
// ===========================
const heroSection = document.querySelector(".hero");
const heroBackground = document.querySelector(".hero-background");
if (heroSection && heroBackground) {
  const canvas = document.createElement("canvas");
  canvas.id = "hero-particle-canvas";
  canvas.style.position = "absolute";
  canvas.style.inset = "0";
  canvas.style.width = "100%";
  canvas.style.height = "100%";
  canvas.style.pointerEvents = "none";
  canvas.style.zIndex = "1";
  heroBackground.appendChild(canvas);

  const ctx = canvas.getContext("2d");
  
  let width = (canvas.width = heroSection.offsetWidth);
  let height = (canvas.height = heroSection.offsetHeight);

  const particles = [];
  const particleCount = 45;

  const colors = [
    "rgba(167, 139, 250, 0.12)", // var(--cg-accent) translucent
    "rgba(139, 92, 246, 0.08)",  // var(--cg-accent-hover) translucent
    "rgba(109, 40, 217, 0.06)",   // var(--cg-accent-dark) translucent
  ];

  class HeroParticle {
    constructor() {
      this.reset();
      this.y = Math.random() * height; // initial random spread
    }

    reset() {
      this.x = Math.random() * width;
      this.y = height + 10;
      this.size = Math.random() * 2.2 + 0.8;
      this.speedY = -(Math.random() * 0.35 + 0.1); // float upwards very slowly
      this.speedX = (Math.random() - 0.5) * 0.15;
      this.color = colors[Math.floor(Math.random() * colors.length)];
      this.alpha = Math.random() * 0.5 + 0.5;
      this.oscillationSpeed = Math.random() * 0.015 + 0.005;
      this.oscillationDistance = Math.random() * 0.4 + 0.1;
      this.time = Math.random() * 100;
    }

    update() {
      this.time += this.oscillationSpeed;
      this.y += this.speedY;
      this.x += this.speedX + Math.sin(this.time) * this.oscillationDistance;

      if (this.y < -10 || this.x < -10 || this.x > width + 10) {
        this.reset();
      }
    }

    draw() {
      ctx.fillStyle = this.color;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  // Initialize particles
  for (let i = 0; i < particleCount; i++) {
    const p = new HeroParticle();
    p.y = Math.random() * height;
    particles.push(p);
  }

  let animationId;
  function animateHeroParticles() {
    ctx.clearRect(0, 0, width, height);

    particles.forEach((p) => {
      p.update();
      p.draw();
    });

    animationId = requestAnimationFrame(animateHeroParticles);
  }

  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  
  function handleMotionPreference(mediaQuery) {
    if (mediaQuery.matches) {
      if (animationId) {
        cancelAnimationFrame(animationId);
      }
      ctx.clearRect(0, 0, width, height);
      particles.forEach((p) => {
        p.draw();
      });
    } else {
      animateHeroParticles();
    }
  }

  handleMotionPreference(prefersReduced);
  prefersReduced.addEventListener("change", handleMotionPreference);

  window.addEventListener("resize", () => {
    width = canvas.width = heroSection.offsetWidth;
    height = canvas.height = heroSection.offsetHeight;
    if (prefersReduced.matches) {
      particles.forEach((p) => {
        p.draw();
      });
    }
  });
}

// ===========================
// Headline Typewriter Effect
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const typewriterSpan = document.getElementById("typewriter");
  if (!typewriterSpan) return;

  const words = ["Cybersecurity", "Threat Detection", "Vulnerability Scan", "Network Security"];
  let wordIndex = 0;
  let charIndex = words[0].length; // Start with the first word complete to prevent SEO/layout shift
  let isDeleting = true;
  let typingSpeed = 150;

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    typewriterSpan.textContent = "Cybersecurity";
    return;
  }

  function type() {
    const currentWord = words[wordIndex];
    
    if (isDeleting) {
      typewriterSpan.textContent = currentWord.substring(0, charIndex - 1);
      charIndex--;
      typingSpeed = 60; // Faster deleting
    } else {
      typewriterSpan.textContent = currentWord.substring(0, charIndex + 1);
      charIndex++;
      typingSpeed = 130; // Custom typing speed
    }

    if (!isDeleting && charIndex === currentWord.length) {
      typingSpeed = 2000; // Pause at the complete word
      isDeleting = true;
    } else if (isDeleting && charIndex === 0) {
      isDeleting = false;
      wordIndex = (wordIndex + 1) % words.length;
      typingSpeed = 500; // Pause before typing the next word
    }

    setTimeout(type, typingSpeed);
  }

  // Initial delay before commencing loop
  setTimeout(type, 1500);
});

// ===========================
// Progress Ring Percentage Count-Up
// ===========================
document.addEventListener("DOMContentLoaded", () => {
  const percentEl = document.getElementById("progressPercent");
  if (!percentEl) return;

  const targetPercent = 98.5;
  
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    percentEl.textContent = `${targetPercent}%`;
    return;
  }

  const duration = 2500; // 2.5s duration
  const startTime = performance.now();

  function easeOutQuad(x) {
    return 1 - (1 - x) * (1 - x);
  }

  function updateCounter(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easedProgress = easeOutQuad(progress);
    
    const currentVal = (easedProgress * targetPercent).toFixed(1);
    percentEl.textContent = `${currentVal}%`;

    if (progress < 1) {
      requestAnimationFrame(updateCounter);
    }
  }

  setTimeout(() => {
    requestAnimationFrame(updateCounter);
  }, 400);
});

// ===========================
// CTA Section Particle Effect
// ===========================
const ctaSection = document.querySelector(".cta");
if (ctaSection) {
  const canvas = document.createElement("canvas");
  canvas.style.position = "absolute";
  canvas.style.top = "0";
  canvas.style.left = "0";
  canvas.style.width = "100%";
  canvas.style.height = "100%";
  canvas.style.pointerEvents = "none";
  canvas.style.opacity = "0.3";
  ctaSection.insertBefore(canvas, ctaSection.firstChild);

  const ctx = canvas.getContext("2d");
  canvas.width = ctaSection.offsetWidth;
  canvas.height = ctaSection.offsetHeight;

  const particles = [];
  const particleCount = 50;

  class Particle {
    constructor() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.size = Math.random() * 3 + 1;
      this.speedX = Math.random() * 1 - 0.5;
      this.speedY = Math.random() * 1 - 0.5;
    }

    update() {
      this.x += this.speedX;
      this.y += this.speedY;

      if (this.x > canvas.width) this.x = 0;
      if (this.x < 0) this.x = canvas.width;
      if (this.y > canvas.height) this.y = 0;
      if (this.y < 0) this.y = canvas.height;
    }

    draw() {
      ctx.fillStyle = "rgba(255, 255, 255, 0.8)";
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  for (let i = 0; i < particleCount; i++) {
    particles.push(new Particle());
  }

  function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    particles.forEach((particle) => {
      particle.update();
      particle.draw();
    });

    // Draw connections
    particles.forEach((a, i) => {
      particles.slice(i + 1).forEach((b) => {
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < 100) {
          ctx.strokeStyle = `rgba(255, 255, 255, ${
            0.2 * (1 - distance / 100)
          })`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      });
    });

    requestAnimationFrame(animateParticles);
  }

  animateParticles();

  // Resize canvas on window resize
  window.addEventListener("resize", () => {
    canvas.width = ctaSection.offsetWidth;
    canvas.height = ctaSection.offsetHeight;
  });
}

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

console.log(
  "%c🛡️ CyberGuard",
  "font-size: 24px; font-weight: bold; color: #667eea;"
);
console.log(
  "%cWelcome to CyberGuard! Your comprehensive cybersecurity toolkit.",
  "font-size: 14px; color: #64748b;"
);
console.log(
  "%cTry the Konami Code for a surprise! ⬆️⬆️⬇️⬇️⬅️➡️⬅️➡️BA",
  "font-size: 12px; color: #8b5cf6;"
);
