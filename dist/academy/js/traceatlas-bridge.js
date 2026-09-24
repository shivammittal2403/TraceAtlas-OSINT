(function(){
  if(document.querySelector('.traceatlas-bridge')) return;
  var path=location.pathname;
  var academyRoot=path.includes('/pages/')||path.includes('/docs/')?'../index.html':'index.html';
  var bar=document.createElement('div');
  bar.className='traceatlas-bridge';
  bar.innerHTML='<a class="traceatlas-bridge__brand" href="/"><span class="traceatlas-bridge__mark">⌁</span><span>TraceAtlas</span></a><nav class="traceatlas-bridge__links" aria-label="TraceAtlas Academy"><a href="'+academyRoot+'">Academy home</a><a href="'+(path.includes('/pages/')?'training.html':'pages/training.html')+'">Training</a><a href="'+(path.includes('/pages/')?'resources.html':'pages/resources.html')+'">Resources</a><a href="/">Tool directory</a></nav>';
  document.body.insertBefore(bar,document.body.firstChild);

  var note=document.createElement('div');
  note.className='traceatlas-attribution';
  note.innerHTML='Academy materials adapted from <a href="https://github.com/FreeOSINT/FreeOSINT.github.io" target="_blank" rel="noopener noreferrer">FreeOSINT</a> under the MIT License. Use only for lawful, ethical research.';
  document.body.appendChild(note);

  document.addEventListener('error',function(event){
    var image=event.target;
    if(image&&image.tagName==='IMG'&&!image.dataset.traceFallback){
      image.dataset.traceFallback='1';
      image.src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1200 675'%3E%3Crect width='1200' height='675' fill='%231b5b43'/%3E%3Cpath d='M180 500L410 150l150 245 170-120 290 225' fill='none' stroke='%23bbf451' stroke-width='34' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";
    }
  },true);
})();
