(function(){
  if(document.querySelector('.traceatlas-bridge')) return;
  var bar=document.createElement('div');
  bar.className='traceatlas-bridge';
  bar.innerHTML='<a class="traceatlas-bridge__brand" href="/"><span class="traceatlas-bridge__mark">⌁</span><span>TraceAtlas</span></a><nav class="traceatlas-bridge__links" aria-label="TraceAtlas Academy"><a href="/academy/">Academy home</a><a href="/academy/training">Training</a><a href="/academy/resources">Resources</a><a href="/">Tool directory</a></nav>';
  document.body.insertBefore(bar,document.body.firstChild);

  var note=document.createElement('div');
  note.className='traceatlas-attribution';
  note.textContent='TraceAtlas Academy is provided under the MIT License. Use these materials only for lawful, ethical research.';
  document.body.appendChild(note);

  document.addEventListener('error',function(event){
    var image=event.target;
    if(image&&image.tagName==='IMG'&&!image.dataset.traceFallback){
      image.dataset.traceFallback='1';
      image.src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1200 675'%3E%3Crect width='1200' height='675' fill='%231b5b43'/%3E%3Cpath d='M180 500L410 150l150 245 170-120 290 225' fill='none' stroke='%23bbf451' stroke-width='34' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";
    }
  },true);
})();
