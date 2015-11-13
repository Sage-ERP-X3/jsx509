"use strict";

var oids = require("./oids");

var types = exports.types = {
	UEOC: 0x0,
	BOOLEAN: 0x1,
	INTEGER: 0x2,
	BITS: 0x3,
	BYTES: 0x4,
	NULL: 0x5,
	OID: 0x6,
	UTF8STRING: 0xc,
	USEQ: 0x10,
	USET: 0x11,
	STRING: 0x13,
	T61STRING: 0x14,
	TIMESTAMP: 0x17,
};

var COMPOSITE = 0x20;
var APPLICATION = 0x40;
var CONTEXT = 0x80;

types.EOC = types.UEOC + CONTEXT + COMPOSITE;
types.SEQ = types.USEQ + COMPOSITE;
types.SET = types.USET + COMPOSITE;

var typeNames = Object.keys(types).reduce(function(r, k) {
	r[types[k]] = k;
	return r;
}, {});

function Node(type, buf, pos, len) {
	this.buf = buf;
	this.type = type;
	this.pos = pos;
	this.len = len;
	this.children = type & 0x20 ? [] : null;
}

exports.createNode = function(type, buf) {
	return new Node(type, buf, 0, buf ? buf.length : 0);
};

var NP = Node.prototype;

NP.add = function(type, buf) {
	// if type is a node, add it.
	var n = type && type.type != null ? type : new Node(type, buf, 0, buf ? buf.length : 0);
	this.children.push(n);
	return n;
};

NP.addSeqOid = function(oid, type, buf) {
	var seq = this.add(types.SEQ);
	seq.add(types.OID, oid);
	return type ? seq.add(types.EOC).add(type, buf) : seq.addNull();
};
NP.addNull = function() {
	return this.add(types.NULL, new Buffer(0));
};

NP.addInt = function(val) {
	if (val < 0 || val >= 128) throw new Error("NIY: sorry only small positive integers supported");
	return this.add(types.INTEGER, new Buffer([val]));
};

NP.addEoc = function(type, buf) {
	return this.add(types.EOC).add(type, buf);
};

NP.addSeq = function() {
	return this.add(types.SEQ);
};

NP.addSet = function() {
	return this.add(types.SET);
};

NP.equals = function(n) {
	if (!n || this.type !== n.type || this.len !== n.len) return false;
	for (var i = 0, len = this.len; i < len; i++) {
		if (this.buf[this.pos + i] !== n.buf[n.pos + i]) return false;
	}
	return true;
};

NP.getData = function() {
	if (this.buf) {
		// assume that bits are always multiples of 8 (therefore ignore number of unused bits) which is the first octet of the bits
		// for integers: strip starting 00 octet (which may be necessary to indicate that the number is positive)
		if (this.type === types.BITS || this.type === types.INTEGER && this.len > 1 && this.buf[this.pos] === 0) return this.buf.slice(this.pos + 1, this.pos + this.len);
		else return this.buf.slice(this.pos, this.pos + this.len);
	} else return new Buffer(0);
};

NP.getMillis = function() {
	if (this.type === types.TIMESTAMP) {
		var timestamp = this.getData().toString();
		var r = /(\d\d)?(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d\d\d)?(Z)?/.exec(timestamp);
		if (r) {
			var t = (r[1] ? r[1] : "20") + r[2] + "-" + r[3] + "-" + r[4] + " " + r[5] + ":" + r[6] + ":" + r[7] + r[9];
			return Date.parse(t);
		}
		throw new Error("Invalid datetime string " + timestamp);
	}
	throw new Error("No datetime");
};

NP.toString = function(pfx) {
	pfx = pfx || '\n';
	var self = this;

	function toStr(node) {
		return node.toString(pfx + '  ');
	}

	function head(s) {
		return pfx + s + " " + self.type.toString(16) + " " + self.len + " ";
	}
	var b = this.getData();
	var t = this.type & 0x1f;
	var name = "" + (typeNames[this.type] || typeNames[t]);
	if (this.type & COMPOSITE) return head(name) + this.children.map(toStr).join('');
	else if (this.type === types.TIMESTAMP) return head(name) + new Date(this.getMillis()).toUTCString();
	else return head(name) + b.toString(t === types.STRING || t === types.T61STRING || t === types.UTF8STRING ? "utf8" : "hex") + (t === types.OID ? ": " + oids.toString(b) : "");
};

var fromBuffer = exports.fromBuffer = function(buf) {
	var pos = 0;

	function readLen() {
		var len = buf[pos++];
		if (len > 0x7f) {
			var l = (len & 0x7f);
			len = 0;
			while (l-- > 0) len = len * 256 + buf[pos++];
		}
		return len;
	}

	function parse1() {
		var type = buf[pos++];
		var len = readLen();
		var node = new Node(type, buf, pos, len);
		var end = pos + len;
		if (type & 0x20) {
			while (pos < end) node.children.push(parse1());
		} else {
			pos += len;
		}

		return node;
	}

	return parse1();
};

var toBuffer = exports.toBuffer = function(node) {
	function llen(l) {
		return l <= 0x7f ? 0 : l <= 0xff ? 1 : l <= 0xffff ? 2 : l <= 0xffffff ? 3 : 4;
	}

	function setLen(v, n) {
		var type = n.type;
		if (type & 0x20) {
			n.len = n.children.reduce(setLen, 0);
		}
		var l = n.len;
		return v + l + 2 + llen(l);
	}
	var len = setLen(0, node);

	var buf = new Buffer(len),
		pos = 0;

	function fillBuf(n) {
		buf[pos++] = n.type;
		var l = n.len;
		if (l <= 0x7f) {
			buf[pos++] = l;
		} else {
			var ll = llen(l);
			buf[pos++] = 0x80 + ll;
			for (var i = ll - 1; i >= 0; i--)
				buf[pos + i] = l % 256, l = Math.floor(l / 256);
			if (l !== 0) throw new Error("internal error writing X509 len: l=" + l);
			pos += ll;
		}
		if (n.type & 0x20) n.children.forEach(fillBuf);
		else {
			n.buf.copy(buf, pos, n.pos, n.pos + n.len);
			pos += n.len;
		}
	}
	fillBuf(node);
	if (pos !== len) throw new Error("internal error X509 end pos=" + pos + ", expected " + len);
	return buf;
};

exports.toString = function(node, enc) {
	return toBuffer(node).toString(enc || "hex");
};

exports.fromString = function(str, enc) {
	return fromBuffer(new Buffer(str, enc || "hex"));
};