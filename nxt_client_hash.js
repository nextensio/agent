//
// NXT Client Hash Map
// Author: Rudy Zulkarnain
// Date: April 4th, 2019
//
var clientHashMap = new Map();

module.exports = {
    clientHashMap,

    createKey: function(srcPort, srcIp) {
        return srcPort + '_' + srcIp;
    },

    insert: function (key, value) {
        return this.clientHashMap.set(key, value);
    },

    delete: function(key) {
        return this.clientHashMap.delete(key);
    },

    get: function (key) {
        return this.clientHashMap.get(key);
    },

};