(function () {
  function addEye(input) {
    if (input.dataset.eye) return;
    input.dataset.eye = '1';

    var wrap = document.createElement('div');
    wrap.style.position = 'relative';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    input.style.paddingInlineEnd = '44px';

    var b = document.createElement('button');
    b.type = 'button';
    b.setAttribute('aria-label', 'إظهار كلمة السر');
    b.textContent = '👁';
    b.style.cssText = 'position:absolute;inset-inline-end:6px;top:50%;transform:translateY(-50%);' +
      'background:none;border:0;padding:6px 10px;font-size:18px;cursor:pointer;color:#6b6f78;width:auto;margin:0';
    b.onclick = function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      b.textContent = show ? '👁' : '👁';
    };
    wrap.appendChild(b);
  }
  document.querySelectorAll('input[type="password"]').forEach(addEye);
})();