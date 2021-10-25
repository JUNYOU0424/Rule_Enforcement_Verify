const fs = require('fs')

let rawdata = fs.readFileSync('trace.json')
let data = JSON.parse(rawdata)
let flow_set = new Array()
let flow = new Array()
let set_count = 0
for(let i=0;i<data.length;i++){
    flow[i] = new Object()
    flow[i].src_port = data[i]._source.layers.eth['eth.src']
    flow[i].dst_port = data[i]._source.layers.eth['eth.dst']
    flow[i].ip_src = data[i]._source.layers.ip['ip.src']
    flow[i].ip_dst = data[i]._source.layers.ip['ip.dst']
    flow[i].proto = data[i]._source.layers.ip['ip.proto']
}
//console.log(flow)
Flow_Classify(flow)

function Flow_Classify(set) {
    flow_set = set.filter(Compare)
    //console.log(flow_set)
}

function Compare(set) {
    for(let i = 0;i < set.length;i++){
            for(let j=1;j<set.length-1;j++){
                if(Object.is(set[i],set[j]))
                    return set[i]
            }
        }
}