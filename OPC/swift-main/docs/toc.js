// This was derived from http://golang.org/doc/godocs.js, which has:
// Except as noted, this content is licensed under Creative Commons
// Attribution 3.0


// Listen to the load event for the document.
if (window.addEventListener) {
  window.addEventListener('load', onload_handler, false);
} else if (window.attachEvent) {
  window.attachEvent('onload', onload_handler);
}

function onload_handler() {
  generateTOC();
  addTopLinks();
}

/* Generates a table of contents: looks for h2 and h3 elements and generates
 * links.  "Decorates" the element with id=="nav" with this table of contents.
 */
function generateTOC() {
  var navbar = document.getElementById('nav');
  if (!navbar) { return; }

  var toc_items = [];

  var i;
  for (i = 0; i < navbar.parentNode.childNodes.length; i++) {
    var node = navbar.parentNode.childNodes[i];
    if ((node.tagName == 'h2') || (node.tagName == 'H2')) {
      if (!node.id) {
        node.id = 'tmp_' + i;
      }
      var text = godocs_nodeToText(node);
      if (!text) { continue; }

      var textNode = document.createTextNode(text);

      var link = document.createElement('a');
      link.href = '#' + node.id;
      link.appendChild(textNode);

      // Then create the item itself
      var item = document.createElement('dt');

      item.appendChild(link);
      toc_items.push(item);
    }
    if ((node.tagName == 'h3') || (node.tagName == 'H3')) {
      if (!node.id) {
        node.id = 'tmp_' + i;
      }
      var text = godocs_nodeToText(node);
      if (!text) { continue; }

      var textNode = document.createTextNode(text);

      var link = document.createElement('a');
      link.href = '#' + node.id;
      link.appendChild(textNode);

      // Then create the item itself
      var item = document.createElement('dd');

      item.appendChild(link);
      toc_items.push(item);
    }
  }

  if (!toc_items.length) { return; }

  var dl1 = document.createElement('dl');
  var dl2 = document.createElement('dl');

  var split_index = (toc_items.length / 2) + 1;
  if (split_index < 8) {
    split_index = toc_items.length;
  }

  for (i = 0; i < split_index; i++) {
    dl1.appendChild(toc_items[i]);
  }
  for (/* keep using i */; i < toc_items.length; i++) {
    dl2.appendChild(toc_items[i]);
  }

  var tocTable = document.createElement('table');
  navbar.appendChild(tocTable);
  tocTable.className = 'unruled';
  var tocBody = document.createElement('tbody');
  tocTable.appendChild(tocBody);

  var tocRow = document.createElement('tr');
  tocBody.appendChild(tocRow);

  // 1st column
  var tocCell = document.createElement('td');
  tocCell.className = 'first';
  tocRow.appendChild(tocCell);
  tocCell.appendChild(dl1);

  // 2nd column
  tocCell = document.createElement('td');
  tocRow.appendChild(tocCell);
  tocCell.appendChild(dl2);
}

/* Returns the "This sweet header" from <h2>This <i>sweet</i> header</h2>.
 * Takes a node, returns a string.
 */
function godocs_nodeToText(node) {
  var TEXT_NODE = 3; // Defined in Mozilla but not MSIE :(

  var text = '';
  for (var j = 0; j != node.childNodes.length; j++) {
    var child = node.childNodes[j];
    if (child.nodeType == TEXT_NODE) {
      if (child.nodeValue != '[Top]') { // Ok, that's a hack, but it works.
        text = text + child.nodeValue;
      }
    } else {
      text = text + godocs_nodeToText(child);
    }
  }
  return text;
}

/* For each H2 heading, add a link up to the #top of the document.
 * (As part of this: ensure existence of 'top' named anchor link
 * (theoretically at doc's top).)
 */
function addTopLinks() {
  /* Make sure there's a "top" to link to. */
  var top = document.getElementById('top');
  if (!top) {
    document.body.id = 'top';
  }

  if (!document.getElementsByTagName) return; // no browser support

  var headers = document.getElementsByTagName('h2');

  for (var i = 0; i < headers.length; i++) {
    var span = document.createElement('span');
    span.className = 'navtop';
    var link = document.createElement('a');
    span.appendChild(link);
    link.href = '#top';
    var textNode = document.createTextNode('[Top]');
    link.appendChild(textNode);
    headers[i].appendChild(span);
  }
}
