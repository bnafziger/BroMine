module datamine;

@load base/utils/exec

global ports = "";
global port_s: set[port] = {};
global port_v: vector of count = {};

global data: bool = F;
global ipport: table[addr] of set[port] = {};

event new_connection(c: connection) {
  if (c$id$resp_h !in ipport ) ipport[c$id$resp_h]=set();
  if (c$id$resp_p !in ipport[c$id$resp_h]) add ipport[c$id$resp_h][c$id$resp_p];
}

event prep () {
  for (i in ipport) {
    for ( ps in ipport[i]) port_v[|port_v|]= port_to_count(ps); 
    sort(port_v);
    for ( pv in port_v) ports += cat(port_v[pv])+" "; 

    local c = open_for_append("/tmp/input.txt");
    print c, ports;
    close(c);

    ports = "";
    port_s = set();
    port_v = vector();
    data=T;
    }

  clear_table (ipport);
  schedule 60sec { prep () };
}

event mine () {
  if ( data )  {
    local jcmd="java -jar /tmp/spmf.jar run AprioriInverse /tmp/input.txt /tmp/output.txt 2% 20% >/dev/null ; tail -n1 /tmp/output.txt";
    local cmd=Exec::Command($cmd=jcmd);
    when ( local result = Exec::run(cmd) ) {
      if ( result?$stdout ) 
        if ( strstr(result$stdout[0], "SUP: 1") == 0 )
          NOTICE([$note=Weird::Activity,$msg=" AprioriInverse Port Knock Detection "+result$stdout[0]]);
      }
  }

  schedule 240sec { mine () };
}

event bro_init() {
  local c = unlink("/tmp/input.txt");
  local o = unlink("/tmp/output.txt");

  schedule 60sec { prep () };
  schedule 240sec { mine () };
}
