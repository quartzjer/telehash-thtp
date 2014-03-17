var stream = require("stream");
var urllib = require("url");

exports.install = function(self)
{
  self.thtp = {};
  self.thtp.request = function(args, cbRequest)
  {
    if(typeof args == "string") args = {uri:args}; // convenience
    if(typeof args != "object" || !(args.uri || args.url || args.hashname)) return errored("invalid args",cbRequest);

    if(args.hashname) args.uri = "thtp://"+args.hashname+args.path;
    args.uri = args.uri || args.url;
    // node's uri parser enforces dns max 63 chars per label, grr!
    var hashname = args.uri.match(/[0-9A-Fa-f]{64}/)[0];
    var uri = urllib.parse(args.uri.replace(hashname,"dummy"));
    uri.hostname = hashname;

    if(uri.protocol != "thtp:") return errored("invalid protocol "+uri.protocol,cbRequest);
    var to;
    if(!(to = self.whois(uri.hostname))) return errored("invalid hashname",cbRequest);
    if(typeof args.method != "string") args.method = "get";

    var http = {body:args.body,js:{}};
    if(typeof args.headers == "object") Object.keys(args.headers).forEach(function(header){
      http.js[header.toLowerCase()] = args.headers[header].toString();
    });
    if(http.body) http.js["content-length"] = http.body.length.toString();
    var phttp = self.pencode(http.js,http.body);

    var js = {method:args.method.toLowerCase(),path:uri.pathname};

    // single-shot requests
    if(phttp.length < 1000) js.end = true;

    console.log("REQUESTING",js,phttp.length);
    var pipe = streamer(to.start("thtp",{bare:true,js:js,body:phttp.slice(0,1000)},function(err,packet,chan,cbChan){
      cbChan();
      if(pipe.headers)
      {
        pipe.push(packet.body);
        if(err) pipe.emit("end");
        return;
      }

      // if parsing headers yet
      phttp = Buffer.concat([phttp,packet.body]);
      if(err && phttp.length == 0) phttp = new Buffer("0000","hex"); // empty request is ok
      var http;
      if(!(http = self.pdecode(phttp))) return;

      if(!http.js.status) http.js.status = packet.js.status;
      pipe.headers = http.js;
      cbRequest(false,pipe);
      if(http.body) pipe.push(http.body);
    }));

    // any remainder
    if(phttp.length > 1000) pipe.end(phttp.slice(1000));

    return pipe;
  }

  self.thtp.listen = function(cbListen)
  {
    self.rels["thtp"] = function(err, packet, chan, cbStart)
    {
      console.log("INCOMING",packet.js,packet.body.length);
      // ensure valid request
      if(typeof packet.js.path != "string" || typeof packet.js.method != "string") return chan.err("invalid request");

      var pipe;
      var phttp = new Buffer(0);
      chan.callback = function(err, packet, chan, cbChan)
      {
        cbChan();
        // just streaming the body
        if(pipe)
        {
          if(packet.body) pipe.push(packet.body);
          if(err) pipe.emit("end");
          return;          
        }
        
        // if parsing headers yet
        phttp = Buffer.concat([phttp,packet.body]);
        if(err && phttp.length == 0) phttp = new Buffer("0000","hex"); // make a blank default request
        if(!(http = self.pdecode(phttp))) return;
        console.log("REQ",http,http.js);
        // new thtp request
        http.js.method = packet.js.method;
        if(!http.js.path) http.js.path = packet.js.path;
        if(typeof http.js.method != "string" || typeof http.js.path != "string") return; // invalid request

        pipe = streamer(chan);
        pipe.headers = http.js;
        cbListen(pipe,function(err,args){
          if(err) return chan.err(err);
          var http = {body:args.body,js:{}};
          if(typeof args.headers == "object") Object.keys(args.headers).forEach(function(header){
            http.js[header.toLowerCase()] = args.headers[header].toString();
          });
          if(http.body) http.js["content-length"] = http.body.length.toString();
          http.js.status = args.status;
          if(!http.js.status) http.js.status = 200;
          var phttp = self.pencode(http.js,http.body);

          var js = {status:args.status};
          if(args.body) js.done = true;
          chan.send({js:js,body:phttp});
          return pipe;
        });
        if(http.body) pipe.push(http.body);
      }
      chan.callback(err,packet,chan,cbStart);
    }
  }
}

// convenience wrapper
function errored(err, cb)
{
  cb(err);
  var pipe = stream.Readable();
  pipe._read = function(){}; // TODO
  pipe.emit("end");
  return pipe;
}

function streamer(chan)
{
  var pipe = stream.Duplex();
  pipe._read = function(){}; // TODO
  pipe.on("finish",function(){
    chan.send({js:{end:true}});
  });
  pipe._write = function(data,enc,cbWrite)
  {
    // chunk it
    while(data.length)
    {
      var chunk = data.slice(0,1000);
      data = data.slice(1000);
      var packet = {js:{},body:chunk};
      // last packet gets confirmed/flag
      if(!data.length)
      {
        packet.callback = cbWrite;
        if(pipe.ended) packet.js.end = true;
      }
      chan.send(packet);
    }
  }
  pipe.end = function(data)
  {
    pipe.ended = true;
    pipe.write(data);
  }
  return pipe;
}