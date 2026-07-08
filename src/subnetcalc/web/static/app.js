// Toggle de campos según la operación seleccionada.
// Script externo para permitir una CSP estricta (script-src 'self').
(function () {
  "use strict";
  var sel = document.getElementById("action");
  if (!sel) return;
  var fields = document.querySelectorAll(".field[data-show]");

  function refresh() {
    var a = sel.value;
    fields.forEach(function (f) {
      var show = f.dataset.show.split(" ").indexOf(a) !== -1;
      f.style.display = show ? "" : "none";
    });
  }

  sel.addEventListener("change", refresh);
  refresh();
})();
