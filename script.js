(function () {
  'use strict';

  // Nav scroll state
  var nav = document.getElementById('nav');
  if (nav) {
    var onScroll = function () {
      if (window.scrollY > 12) nav.classList.add('is-stuck');
      else nav.classList.remove('is-stuck');
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  // Mobile nav toggle
  var toggle = document.querySelector('.nav__toggle');
  var navLinks = document.getElementById('nav-links');
  function setMenu(open) {
    if (!toggle || !navLinks) return;
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    navLinks.classList.toggle('is-open', open);
  }
  if (toggle && navLinks) {
    toggle.addEventListener('click', function () {
      var open = toggle.getAttribute('aria-expanded') === 'true';
      setMenu(!open);
    });
    navLinks.querySelectorAll('a').forEach(function (a) {
      a.addEventListener('click', function () { setMenu(false); });
    });
    document.addEventListener('click', function (e) {
      if (!navLinks.classList.contains('is-open')) return;
      if (e.target === toggle || toggle.contains(e.target)) return;
      if (navLinks.contains(e.target)) return;
      setMenu(false);
    });
  }

  // Apply modal
  var modal = document.getElementById('apply-modal');
  var lastFocus = null;
  function openModal() {
    if (!modal) return;
    lastFocus = document.activeElement;
    modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    var firstInput = modal.querySelector('input, button');
    if (firstInput) firstInput.focus();
  }
  function closeModal() {
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  }
  document.querySelectorAll('[data-open-apply]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      e.preventDefault();
      openModal();
    });
  });
  document.querySelectorAll('[data-close-apply]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      e.preventDefault();
      closeModal();
    });
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && modal && modal.getAttribute('aria-hidden') === 'false') closeModal();
  });

  // Reveal-on-scroll: fade up section heads, stagger child grids
  if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    document.querySelectorAll('.reveal, .reveal-stagger').forEach(function (el) {
      io.observe(el);
    });
  } else {
    // Fallback / reduced motion: show everything immediately.
    document.querySelectorAll('.reveal, .reveal-stagger').forEach(function (el) {
      el.classList.add('is-visible');
    });
  }

  // Notify form — captures launch-interest emails to Supabase (via the
  // notify-signup function) so the list actually reaches the program. Shows
  // success optimistically; a local stash is kept only as a network fallback.
  var form = document.getElementById('notify-form');
  var success = document.getElementById('notify-success');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = form.querySelector('input[name="email"]');
      var email = input && input.value ? input.value.trim() : '';
      if (!email || email.indexOf('@') < 1) {
        input && input.focus();
        return;
      }
      form.style.display = 'none';
      success.hidden = false;
      fetch('/.netlify/functions/notify-signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      }).catch(function () {
        // Network failure: keep a local copy so nothing is silently lost.
        try {
          var stash = JSON.parse(localStorage.getItem('nn_notify') || '[]');
          stash.push({ email: email, at: new Date().toISOString() });
          localStorage.setItem('nn_notify', JSON.stringify(stash));
        } catch (_) {}
      });
    });
  }
})();
