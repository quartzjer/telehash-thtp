var path = require("path");
var th = require("telehash");
var seeds = require("./seeds.json");
//th.debug(console.log);
th.init({id:path.resolve("server.json"),seeds:seeds},function(err,self){
  if(err) return console.log(err);
  require("./index.js").install(self);
  self.thtp.listen(function(req,cbRes){
    console.log("got request",req.headers);
    cbRes({status:200,body:"ok"});
//    cbRes().end("foobar");
//    process.stdin.pipe(cbRes());
  });
  console.log("listening at thtp://"+self.hashname+"/")
})