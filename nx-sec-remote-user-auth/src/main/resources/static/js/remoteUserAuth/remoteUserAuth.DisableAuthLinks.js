Ext.override(Sonatype.headLinks, {
  
  updateLeftWhenLoggedOut : function(linkEl) {
    linkEl.update('');
    linkEl.removeAllListeners();
    linkEl.setStyle({
        'display' : 'none',
      });
      
      linkEl.on(
        'click',
        function() {
//          alert( 'Disabled' );
          return false;
        }, 
        this
      );
  },
  
  updateMiddleWhenLoggedOut : function(linkEl) {
    linkEl.update('');
    linkEl.update(' | ');
  },
  
  updateLeftWhenLoggedIn : function(linkEl) {
    linkEl.removeAllListeners();
    linkEl.update(Sonatype.user.curr.username);
    
    linkEl.setStyle({
      'color' : 'black',
      'cursor' : 'default',
      'text-align' : 'right'
    });
    
    linkEl.on(
      'click', 
      function() {
    	  return false;
      }, 
      this
    );
  }
  
});
