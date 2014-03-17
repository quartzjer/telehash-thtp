var path = require("path");
var th = require("telehash");
//th.debug(console.log);
th.init({id:path.resolve("server.json"),seeds:path.resolve("seeds.json")},function(err,self){
  if(err) return console.log(err);
  require("./index.js").install(self);
  self.thtp.listen(function(req,cbRes){
    console.log("got request",req.headers);
    cbRes(false,{status:200,body:"ok"});
  });
  console.log("listening at thtp://"+self.hashname+"/")
})