import crypto from 'crypto';
import { nodeText, dumpXML, nodeAsArray, calcHmac, calcDigest } from './utils.js';

const STATES = {
	WAIT_FOR_READY:		0,
	DISCOVER_ALL:		1,
	CONFIRM_UPGRADE:	2,
	FAKE_UPGRADE:		3,
	DONE:				10
};

const AUTH_STAGE = {
	NONE:	0,
	BASIC:	1,
	MAC:	2,
	DONE:	3
};

class SwuotaResponseBuilder {
	constructor(session) {
		this.session = session;
		this.cmd_id = 1;
		this.body = {};
	}
	
	command(name, fields) {
		fields = fields || {};
		
		let json = {
			CmdID: {_text: this.cmd_id++},
			...fields
		};
		
		this.body[name] = this.body[name] || [];
		this.body[name].push(json);
		
		return json;
	}
	
	get(uri) {
		return this.command('Get', {
			Item: {Target: {LocURI: {_text: uri}}}
		});
	}
	
	choice(items) {
		let item_nodes = [];
		for (let item of items)
			item_nodes.push({Data: {_text: item}});
		
		return this.command('Alert', {
			Data: {_text: 1103},
			Item: item_nodes
		});
	}
	
	alert(text, optional) {
		optional = optional || "";
		
		return this.command('Alert', {
			Data: {_text: 1100},
			Item: [
				{Data: {_text: optional}},
				{Data: {_text: text}},
			]
		});
	}
	
	confirm(text, optional) {
		optional = optional || "";
		
		return this.command('Alert', {
			Data: {_text: 1101},
			Item: [
				{Data: {_text: optional}},
				{Data: {_text: text}},
			]
		});
	}
	
	status(code, ref_cmd_name, ref_cmd) {
		return this.command('Status', {
			Data: {_text: code},
			MsgRef: {_text: this.session.client_msg_id},
			CmdRef: {_text: nodeText(ref_cmd.CmdID)},
			Cmd: {_text: ref_cmd_name},
		});
	}
	
	authStatus(code, type, nonce) {
		let extra_data = {};
		
		if (type) {
			extra_data = {
				Chal: {
					Meta: {
						Type: {_attributes: {xmlns: 'syncml:metinf'}, _text: type},
						Format: {_attributes: {xmlns: 'syncml:metinf'}, _text: 'b64'},
					}
				}
			};
			
			if (nonce)
				extra_data.Chal.Meta.NextNonce = {_attributes: {xmlns: 'syncml:metinf'}, _text: nonce};
		}
		
		return this.command('Status', {
			MsgRef: {_text: this.session.client_msg_id},
			CmdRef: {_text: 0},
			Cmd: {_text: 'SyncHdr'},
			TargetRef: {_text: this.session.server_id},
			SourceRef: {_text: this.session.device_id},
			Data: {_text: code},
			...extra_data
		});
	}
	
	final() {
		this.body.Final = [{}];
	}
	
	build() {
		this.session.server_msg_id++;
		
		return {
			_declaration: {_attributes: {version: "1.0"}},
			_doctype: "SyncML PUBLIC \"-//SYNCML//DTD SyncML 1.1//EN\" \"http://www.syncml.org/docs/syncml_represent_v11_20020213.dtd\"",
			SyncML: {
				_attributes: {xmlns: "SYNCML:SYNCML1.1"},
				SyncHdr: {
					VerDTD: {_text: '1.1'},
					VerProto: {_text: 'DM/1.1'},
					SessionID: {_text: this.session.session_id},
					MsgID: {_text: this.session.server_msg_id},
					Target: {LocURI: {_text: this.session.device_id}},
					Source: {LocURI: {_text: this.session.server_id}},
				},
				SyncBody: this.body
			}
		};
	}
}

export class SwuotaServer {
	constructor(users_creds) {
		this.states = {
			[STATES.WAIT_FOR_READY]:	(...args) => this.stateWaitForReady(...args),
			[STATES.DISCOVER_ALL]:		(...args) => this.stateDiscoverAll(...args),
			[STATES.CONFIRM_UPGRADE]:	(...args) => this.stateConfirmUpgrade(...args),
			[STATES.FAKE_UPGRADE]:		(...args) => this.stateFakeUpgrade(...args),
			[STATES.DONE]:				(...args) => this.stateDone(...args),
		};
		this.server_auth = false;
		this.session_id = false;
		
		this.users_creds = {};
		for (let user of users_creds)
			this.users_creds[user.login] = user;
	}
	
	init(request) {
		this.session_id = +nodeText(request.SyncML.SyncHdr.SessionID);
		
		this.state = STATES.WAIT_FOR_READY;
		this.client_msg_id = +nodeText(request.SyncML.SyncHdr.MsgID);
		this.client_cmd_id = 0;
		this.server_msg_id = 1;
		this.server_cmd_id = 0;
		this.tmp = {};
		
		this.server_id = nodeText(request.SyncML.SyncHdr.Target.LocURI);
		this.device_id = nodeText(request.SyncML.SyncHdr.Source.LocURI);
		
		this.nonce = false;
		this.is_auth = false;
		let login = nodeText(request.SyncML.SyncHdr.Source.LocName);
		this.user = this.users_creds[login];
		this.props = {};
		this.command_result_keys = {};
		
		this.meta = {
			maxMsgSize:		+nodeText(request.SyncML.SyncHdr.Meta.MaxMsgSize),
			maxObjSize:		+nodeText(request.SyncML.SyncHdr.Meta.MaxObjSize)
		};
		
		if (this.user) {
			console.log(`[${this.device_id}] new session #${this.session_id} initiated [user: ${this.user.login}].`);
		} else {
			console.log(`[${this.device_id}] new session #${this.session_id} initiated by UNKNOWN user.`);
		}
	}
	
	parseAuthCred(cred) {
		if (!cred)
			return false;
		
		let auth_type = nodeText(cred.Meta.Type);
		if (auth_type != 'syncml:auth-basic') {
			console.log(`ERROR: ${auth_type} not supported!`);
			return false;
		}
		
		let [login, password] = Buffer.from(nodeText(cred.Data), 'base64').toString().split(':');
		if (login != this.user.login) {
			console.log(`ERROR: login ${login} != ${this.user.login}`);
			return false;
		}
		
		if (this.user.password != password) {
			console.log(`ERROR: invalid password for ${login}! [password=${password}]`);
			return false;
		}
		
		return true;
	}
	
	parseMacNonce(chal) {
		if (!chal)
			return false;
		let auth_type = nodeText(chal.Meta.Type);
		if (auth_type != 'syncml:auth-MAC')
			return false;
		return nodeText(chal.Meta.NextNonce);
	}
	
	processAuth(request, response) {
		// 401 for unknown users
		if (!this.user) {
			response.authStatus(401);
			return;
		}
		
		// Next nonce for hmac
		if (request.SyncML.SyncBody.Status) {
			for (let status of nodeAsArray(request.SyncML.SyncBody.Status)) {
				if (status.Cmd && nodeText(status.Cmd) == "SyncHdr")
					this.nonce = this.parseMacNonce(status.Chal);
			}
		}
		
		if (this.is_auth) {
			// Already have uath
			response.authStatus(212);
		} else {
			this.is_auth = this.parseAuthCred(request.SyncML.SyncHdr?.Cred);
			
			if (this.is_auth) {
				// Auth success
				console.log(`[${this.device_id}] authenticated by login=${this.user.login}`);
				response.authStatus(212);
			} else {
				// Require auth from client
				console.log(`[${this.device_id}] server required auth.`);
				response.authStatus(407, 'syncml:auth-basic');
			}
		}
	}
	
	getAuthMac(message_body_md5) {
		if (this.nonce) {
			let decoded_nonce = Buffer.from(this.nonce, 'base64');
			let mac = calcHmac(this.user.server_login, this.user.server_password, decoded_nonce, message_body_md5);
			return `algorithm=MD5, username="${this.user.server_login}", mac=${mac}`;
		}
		return false;
	}
	
	handle(request) {
		this.client_msg_id = +nodeText(request.SyncML.SyncHdr.MsgID);
		
		console.log(`----request`);
		
		//console.log("Request:", dumpXML(request));
		
		if (this.session_id !== +nodeText(request.SyncML.SyncHdr.SessionID))
			this.init(request);
		
		let response = new SwuotaResponseBuilder(this);
		this.processAuth(request, response);
		
		let cmd_results = {};
		
		for (let cmd_name in request.SyncML.SyncBody) {
			for (let cmd of nodeAsArray(request.SyncML.SyncBody[cmd_name])) {
				if (this.user) {
					if (cmd_name == 'Replace') {
						for (let item of nodeAsArray(cmd.Item)) {
							let key = nodeText(item.Source.LocURI);
							let value = nodeText(item.Data);
							console.log(`[${this.device_id}] replace ${key} -> ${value}`);
							this.props[key] = value;
						}
					}
				}
				
				if (cmd_name == 'Results' && cmd.CmdRef) {
					let cmd_ref_id = nodeText(cmd.CmdRef);
					let key = this.command_result_keys[cmd_ref_id];
					if (key) {
						cmd_results[key] = cmd_results[key] || {code: false, result: []};
						cmd_results[key].result = cmd_results[key].result.concat(nodeAsArray(cmd.Item));
					}
				}
				
				if (cmd_name == 'Status' && cmd.CmdRef) {
					let cmd_ref_id = nodeText(cmd.CmdRef);
					let key = this.command_result_keys[cmd_ref_id];
					if (key) {
						cmd_results[key] = cmd_results[key] || {code: false, result: []};
						cmd_results[key].code = nodeText(cmd.Data);
					}
				}
				
				if (cmd_name != 'Final' && cmd_name != 'Status') {
					response.status(200, cmd_name, cmd);
				}
			}
		}
		
		this.command_result_keys = {};
		
		if (this.user) {
			this.states[this.state](request, response, cmd_results);
		}
		
		response.final();
		
		let json = response.build();
		//console.log("Response:", dumpXML(json));
		return json;
	}
	
	bindToResult(cmd, key) {
		this.command_result_keys[nodeText(cmd.CmdID)] = key;
	}
	
	stateWaitForReady(request, response, results) {
		if (results.sw_version && results.sw_version.code == 200) {
			console.log(`[${this.device_id}] is ready!!!`);
			
			console.log(results.sw_version.result);
			
			this.props["./DevDetail/SwV"] = nodeText(results.sw_version.result[0].Data);
			
			this.stateConfirmUpgrade(request, response, {});
			this.state = STATES.CONFIRM_UPGRADE;
		//	this.stateDiscoverAll(request, response, {});
		} else {
			console.log(`[${this.device_id}] waiting for ready...`);
			this.bindToResult(response.get('./DevDetail/SwV'), 'sw_version');
		}
	}
	
	stateConfirmUpgrade(request, response, results) {
		if (results.upgrade_confirm) {
			if (results.upgrade_confirm.code == 200) {
				this.stateFakeUpgrade(request, response, {});
				this.state = STATES.FAKE_UPGRADE;
			} else {
				this.state = STATES.DONE;
			}
		} else {
			this.bindToResult(response.confirm(
				'Firmware-Update gefunden: SVN:' + (+this.props["./DevDetail/SwV"] + 1) + '. Es müssen 1,3 MB heruntergeladen werden. Weitermachen?',
				'MINDT=60'
			), 'upgrade_confirm');
		}
	}
	
	stateFakeUpgrade(request, response, results) {
		response.alert('Error! Please, see more info at: https://global-repair-management.com/error9379992', 'MINDT=300');
		this.state = STATES.DONE;
	}
	
	stateDone(request, response, results) {
		// Nothing todo
	}
	
	stateDiscoverAll(request, response, results) {
		if (results.discover_result) {
			console.log(results.discover_result);
			let nodes_to_fetch = [];
			for (let result of results.discover_result.result) {
				let result_type = nodeText(result.Meta.Format);
				let result_data = nodeText(result.Data);
				let root_node = nodeText(result.Source.LocURI);
				
				if (result_type == 'node' && result_data) {
					console.log(`Nodes in ${root_node}`);
					for (let node of result_data.split('/')) {
						console.log(` -> ${root_node}/${node}`);
						this.bindToResult(response.get(`${root_node}/${node}`), 'discover_result');
					}
				} else {
					console.log(`result_data=${result_data}, result_type=${result_type}, root_node=${root_node}`);
				}
			}
		} else {
			console.log(`[${this.device_id}] waiting for discovery...`);
			this.bindToResult(response.get('.'), 'discover_result');
		}
	}
};
