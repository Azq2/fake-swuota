import child_process from 'child_process';
import crypto from 'crypto';
import xmljs from 'xml-js';

export function dumpXML(node) {
	return xmljs.json2xml(node, {compact: true, spaces: 1});
}

export function nodeAsArray(node) {
	if (Array.isArray(node))
		return node;
	return [node];
}

export function nodeText(node) {
	return node ? node._text || node._cdata : node;
}

export function fromWBXML(wbxml) {
	let result = child_process.spawnSync('wbxml2xml', ['-k', '-o', '-', '-'], { input: wbxml, stdio: 'pipe' });
	
	let xml_string = result.output[1].toString();
	
	try {
		return JSON.parse(xmljs.xml2json(xml_string, {compact: true}));
	} catch (e) {
		console.error(`Invalid XML:\n${xml_string}`);
		console.error(e);
		return false;
	}
}

export function toWBXML(xml) {
	let xml_string = xmljs.json2xml(xml, {compact: true});
	let result = child_process.spawnSync('xml2wbxml', ['-v', '1.2', '-o', '-', '-'], { input: xml_string, stdio: 'pipe' });
	return result.output[1];
}

// H(B64(H(username:password)):nonce)
export function calcDigest(username, password, nonce) {
	return crypto.createHash('md5').update(Buffer.concat([
		Buffer.from(crypto.createHash('md5').update(`${username}:${password}`).digest().toString('base64')),
		Buffer.from(':'),
		nonce
	])).digest().toString('base64');
}

// H(B64(H(username:password)):nonce:B64(H(message body)))
export function calcHmac(username, password, nonce, message_body_md5) {
	return crypto.createHash('md5').update(Buffer.concat([
		Buffer.from(crypto.createHash('md5').update(`${username}:${password}`).digest().toString('base64')),
		Buffer.from(':'),
		nonce,
		Buffer.from(':'),
		Buffer.from(message_body_md5.toString('base64'))
	])).digest().toString('base64');
}
