var stream = require("stream");
var urllib = require("url");

exports.install = function(self)
{
  self.thtp = {};
  self.thtp.request = function(args, cbRequest)
  {
    if(typeof args == "string") args = {uri:args}; // convenience
    if(typeof args != "object" || !(args.uri || args.url || args.hashname)) return cbRequest("invalid args")&&false;

    if(args.hashname) args.uri = "thtp://"+args.hashname+args.path;
    args.uri = args.uri || args.url;
    // node's uri parser enforces dns max 63 chars per label, grr!
    var hashname = args.uri.match(/[0-9A-Fa-f]{64}/)[0];
    var uri = urllib.parse(args.uri.replace(hashname,"dummy"));
    uri.hostname = hashname;

    if(uri.protocol != "thtp:") return cbRequest("invalid protocol "+uri.protocol)&&false;
    var to;
    if(!(to = self.whois(uri.hostname))) return cbRequest("invalid hashname")&&false;
    if(typeof args.method != "string") args.method = "get";

    var http = {body:args.body,js:{}};
    if(typeof args.headers == "object") Object.keys(args.headers).forEach(function(header){
      http.js[header.toLowerCase()] = args.headers[header].toString();
    });
    if(http.body) http.js["content-length"] = http.body.length.toString();
    var phttp = self.pencode(http);

    var js = {method:args.method.toLowerCase(),path:uri.pathname};
    // empty requests
    if(["get","head"].indexOf(js.method) >= 0 || args.body) js.done = true;

    var res;
    phttp = new Buffer(0);
    console.log("REQUESTING",js)
    var chan = to.start("thtp",{bare:true,js:js,body:phttp},function(err,packet,cbChan){
      // handle error differently depending on state
      if(err && err !== true)
      {
        if(!res) return cbRequest(err);
        return res.end();
      }
      cbChan();
      // if parsing headers yet
      if(!res)
      {
        phttp = Buffer.concat([phttp,packet.body]);
        if(packet.js.done && phttp.length == 0) phttp = new Buffer("0000","hex"); // empty request is ok
        if((http = self.pdecode(phttp)))
        {
          packet.body = http.body;
          if(!http.js.status) http.js.status = packet.js.status;
          res = stream.Readable();
          res._read = function(){}; // TODO
          res.headers = http.js;
          cbRequest(false,res);
        }
      }
      if(res) res.push(packet.body);
      if(packet.js.done) res.end();
    });

    return writer(chan);
  }

  self.thtp.listen = function(cbListen)
  {
    self.rels["thtp"] = function(err, packet, chan, cbStart)
    {
      console.log("INCOMING",packet.js);
      // ensure valid request
      if(typeof packet.js.path != "string" || typeof packet.js.method != "string") return chan.err("invalid request");

      cbStart();
      var req;
      var phttp = new Buffer(0);
      chan.callback = function(err, packet, chan, cbChan)
      {
        if(err && err !== true)
        {
          // only care if during request reading
          if(req) req.end();
          return;
        }
        // if parsing headers yet
        if(!req)
        {
          phttp = Buffer.concat([phttp,packet.body]);
          if(packet.js.done && phttp.length == 0) phttp = new Buffer("0000","hex"); // empty request is ok
          if((http = self.pdecode(phttp)))
          {
            packet.body = http.body;
            http.js.status = packet.js.status;
            if(!http.js.path) http.js.path = packet.js.path;
            req = stream.Readable();
            req.headers = http.js;
            req._read = function(){}; // TODO
            cbListen(req,function(err,args){
              if(err) return chan.err(err);
              var http = {body:args.body,js:{}};
              if(typeof args.headers == "object") Object.keys(args.headers).forEach(function(header){
                http.js[header.toLowerCase()] = args.headers[header].toString();
              });
              if(http.body) http.js["content-length"] = http.body.length.toString();
              http.js.status = args.status;
              var phttp = self.pencode(http);

              var js = {status:args.status};
              if(args.body) js.done = true;
              chan.send({js:js,body:phttp});
              return writer(chan);
            });
          }
        }
        if(res) res.push(packet.body);
        if(packet.js.done) res.end();
      }
    }
  }
}

function writer(chan)
{
  var ret = stream.Writable();
  ret.on("finish",function(){
    chan.send({js:{done:true,end:true}});
  });
  ret._write = function(data,enc,cbWrite)
  {
    // chunk it
    while(data.length)
    {
      var chunk = data.slice(0,1000);
      data = data.slice(1000);
      var packet = {js:{},body:chunk};
      // last packet gets confirmed/flag
      if(!data.length) packet.callback = cbWrite;
      chan.send(packet);
    }
  }
  return ret;
}