const fs = require('fs')

let rawdata = fs.readFileSync('trace2.json')
let data = JSON.parse(rawdata)
let flow_set = new Array()
let flow = new Array()
let set_count = 0
for (let i = 0; i < data.length; i++) {
    flow[i] = new Object()
    flow[i].src_port = data[i]._source.layers.eth['eth.src']
    flow[i].dst_port = data[i]._source.layers.eth['eth.dst']
    flow[i].ip_src = data[i]._source.layers.ip['ip.src']
    flow[i].ip_dst = data[i]._source.layers.ip['ip.dst']
    flow[i].proto = data[i]._source.layers.ip['ip.proto']
}
Flow_Classify(flow)

function Flow_Classify(set) {
    flow_set[set_count] = []
    for (let i = 0; i < set.length-1; i++) {
        if(set[i]!=0)
            flow_set[set_count].push(data[i])
        for (let j = i + 1; j < set.length; j++) {
            if (Compare(set[i], set[j])) {
                flow_set[set_count].push(data[j])
                set[j] = 0
            }
            else if (j == set.length - 1) {
                //console.log(flow_set[set_count],set_count)
                set_count++
                flow_set[set_count] = []
            }
        }
    }
}
function Compare(a, b) {
    if (a.src_port == b.src_port & a.dst_port == b.dst_port & a.ip_src == b.ip_src & a.ip_dst == b.ip_dst & a.proto == b.proto)
        return true
}

console.log(flow_set)