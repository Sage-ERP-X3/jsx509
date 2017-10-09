import * as oids from './oids';
import { Dict } from './oids';

export const types: Dict<number> = {
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

const COMPOSITE = 0x20;
//var APPLICATION = 0x40;
const CONTEXT = 0x80;

types.EOC = types.UEOC + CONTEXT + COMPOSITE;
types.SEQ = types.USEQ + COMPOSITE;
types.SET = types.USET + COMPOSITE;

const typeNames = Object.keys(types).reduce(function (r, k) {
	r[types[k]] = k;
	return r;
}, {} as Dict<string>);

export class Node {
	buf?: Buffer;
	type: number;
	pos: number;
	len: number;
	children: Node[] | null;
	constructor(type: number, buf: Buffer, pos: number, len: number) {
		this.buf = buf;
		this.type = type;
		this.pos = pos;
		this.len = len;
		this.children = type & 0x20 ? [] : null;
	}
	add(type: Node | number, buf?: Buffer) {
		// if type is a node, add it.
		const n = type instanceof Node ? type : new Node(type, buf!, 0, buf ? buf.length : 0);
		this.children!.push(n);
		return n;
	}
	addSeqOid(oid: Buffer, type?: number, buf?: Buffer) {
		const seq = this.add(types.SEQ);
		seq.add(types.OID, oid);
		return type ? seq.add(types.EOC).add(type, buf) : seq.addNull();
	}
	addNull() {
		return this.add(types.NULL, new Buffer(0));
	}
	addInt(val: number) {
		if (val < 0 || val >= 128) throw new Error('NIY: sorry only small positive integers supported');
		return this.add(types.INTEGER, new Buffer([val]));
	}
	addEoc(type: Node | number, buf?: Buffer) {
		return this.add(types.EOC).add(type, buf);
	}
	addSeq() {
		return this.add(types.SEQ);
	}
	addSet() {
		return this.add(types.SET);
	}
	equals(n: Node) {
		if (!n || this.type !== n.type || this.len !== n.len) return false;
		for (let i = 0, len = this.len; i < len; i++) {
			if (this.buf![this.pos + i] !== n.buf![n.pos + i]) return false;
		}
		return true;
	}
	getData() {
		if (this.buf) {
			// assume that bits are always multiples of 8 (therefore ignore number of unused bits) which is the first octet of the bits
			// for integers: strip starting 00 octet (which may be necessary to indicate that the number is positive)
			if (this.type === types.BITS || this.type === types.INTEGER && this.len > 1 && this.buf[this.pos] === 0) return this.buf.slice(this.pos + 1, this.pos + this.len);
			else return this.buf.slice(this.pos, this.pos + this.len);
		} else return new Buffer(0);
	}
	getMillis() {
		if (this.type === types.TIMESTAMP) {
			const timestamp = this.getData().toString();
			const r = /(\d\d)?(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\.\d\d\d)?(Z)?/.exec(timestamp);
			if (r) {
				const t = (r[1] ? r[1] : '20') + r[2] + '-' + r[3] + '-' + r[4] + ' ' + r[5] + ':' + r[6] + ':' + r[7] + r[9];
				return Date.parse(t);
			}
			throw new Error('Invalid datetime string ' + timestamp);
		}
		throw new Error('No datetime');
	}
	toString(pfx?: string): string {
		pfx = pfx || '\n';
		const self = this;

		function toStr(node: Node) {
			return node.toString(pfx + '  ');
		}

		function head(s: string) {
			return pfx + s + ' ' + self.type.toString(16) + ' ' + self.len + ' ';
		}
		const b = this.getData();
		const t = this.type & 0x1f;
		const name = '' + (typeNames[this.type] || typeNames[t]);
		if (this.type & COMPOSITE) return head(name) + this.children!.map(toStr).join('');
		else if (this.type === types.TIMESTAMP) return head(name) + new Date(this.getMillis()).toUTCString();
		else return head(name) + b.toString(t === types.STRING || t === types.T61STRING || t === types.UTF8STRING ? 'utf8' : 'hex') + (t === types.OID ? ': ' + oids.toString(b) : '');
	}
}

export function createNode(type: number, buf?: Buffer) {
	return new Node(type, buf, 0, buf ? buf.length : 0);
}

export function fromBuffer(buf: Buffer) {
	let pos = 0;

	function readLen() {
		let len = buf[pos++];
		if (len > 0x7f) {
			let l = (len & 0x7f);
			len = 0;
			while (l-- > 0) len = len * 256 + buf[pos++];
		}
		return len;
	}

	function parse1() {
		const type = buf[pos++];
		const len = readLen();
		const node = new Node(type, buf, pos, len);
		const end = pos + len;
		if (type & 0x20) {
			while (pos < end) node.children!.push(parse1());
		} else {
			pos += len;
		}

		return node;
	}

	return parse1();
}

export function toBuffer(node: Node) {
	function llen(l: number) {
		return l <= 0x7f ? 0 : l <= 0xff ? 1 : l <= 0xffff ? 2 : l <= 0xffffff ? 3 : 4;
	}

	function setLen(v: number, n: Node) {
		const type = n.type;
		if (type & 0x20) {
			n.len = n.children!.reduce(setLen, 0);
		}
		const l = n.len;
		return v + l + 2 + llen(l);
	}
	const len = setLen(0, node);

	const buf = new Buffer(len);
	let pos = 0;

	function fillBuf(n: Node) {
		buf[pos++] = n.type;
		let l = n.len;
		if (l <= 0x7f) {
			buf[pos++] = l;
		} else {
			const ll = llen(l);
			buf[pos++] = 0x80 + ll;
			for (let i = ll - 1; i >= 0; i--) {
				buf[pos + i] = l % 256, l = Math.floor(l / 256);
			}
			if (l !== 0) throw new Error('internal error writing X509 len: l=' + l);
			pos += ll;
		}
		if (n.type & 0x20) n.children!.forEach(fillBuf);
		else {
			n.buf!.copy(buf, pos, n.pos, n.pos + n.len);
			pos += n.len;
		}
	}
	fillBuf(node);
	if (pos !== len) throw new Error('internal error X509 end pos=' + pos + ', expected ' + len);
	return buf;
}

exports.toString = function (node: Node, enc?: string) {
	return toBuffer(node).toString(enc || 'hex');
};

exports.fromString = function (str: string, enc?: string) {
	return fromBuffer(new Buffer(str, enc || 'hex'));
};