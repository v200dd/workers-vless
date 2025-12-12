import {
	connect
} from 'cloudflare:sockets';

const te = new TextEncoder();
const td = new TextDecoder();

/**
 * 获取请求模式的连接顺序
 * @param {string} mode - 请求模式 ('d', 's', 'g', 'p', 'h', 'gh')
 * @returns {string[]} - 连接尝试顺序数组
 */
function getOrder(mode) {
	const orderCache = {
		'p': ['d', 'p'],
		's': ['d', 's'],
		'g': ['s'],
		'h': ['d', 'h'],
		'gh': ['h'],
		'default': ['d']
	};
	return orderCache[mode] || orderCache['default'];
}

export default {
	async fetch(req, env) {

		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const u = new URL(req.url);
			let mode = 'd'; // default mode
			let skJson;
			// 修复处理URL编码的查询参数
			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}
			let sParam = u.pathname.split('/s=')[1];
			let pParam;
			let hParam;
			if (sParam) {
				mode = 's';
				skJson = getSKJson(sParam);
			} else {
				const gParam = u.pathname.split('/g=')[1];
				if (gParam) {
					sParam = gParam;
					skJson = getSKJson(gParam);
					mode = 'g';
				} else {
					pParam = u.pathname.split('/p=')[1];
					if (pParam) {
						mode = 'p';
					} else {
						hParam = u.pathname.split('/h=')[1];
						if (hParam) {
							skJson = getSKJson(hParam);
							mode = 'h';
						} else {
							hParam = u.pathname.split('/gh=')[1];
							if (hParam) {
								skJson = getSKJson(hParam);
								mode = 'gh';
							}
						}
					}
				}
			}
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();


			let remote = null, udpWriter = null, isDNS = false;

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
						} catch { }
					}
				}
			}, { highWaterMark: 65536 }).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					// 最小长度检查已调整：去除了16字节UUID，最小长度变为8。
					if (data.byteLength < 8) return;

					// !!! 已移除 UUID 验证: if (!verifyUUID(data)) return;

					const view = new DataView(data);
					// 偏移量已调整: 从 17 变为 1
					const optLen = view.getUint8(1);

					// 偏移量已调整: 从 18 + optLen 变为 2 + optLen
					const cmd = view.getUint8(2 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					// 偏移量已调整: 从 19 + optLen 变为 3 + optLen
					let pos = 3 + optLen;

					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr =
							`${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = td.decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos)
							.toString(16));
						addr = ipv6.join(':');
					} else return;

					// data[0] 仍然是 Type 字节
					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// UDP DNS
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const {
							readable,
							writable
						} = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2))
										.getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(
										'https://1.1.1.1/dns-query', {
										method: 'POST',
										headers: {
											'content-type': 'application/dns-message'
										},
										body: query
									});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp
											.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] :
											header), result
											.length >> 8, result
											.length & 0xff, ...result
										]));
										sent = true;
									}
								} catch { }
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					// TCP连接
					let sock = null;
					for (const method of getOrder(mode)) {
						try {
							if (method === 'd') {
								sock = connect({
									hostname: addr,
									port
								});
								await sock.opened;
								break;
							} else if (method === 's' && skJson) {
								sock = await sConnect(addr, port, skJson);
								break;
							} else if (method === 'p' && pParam) {
								const [ph, pp = port] = pParam.split(':');
								sock = connect({
									hostname: ph,
									port: +pp || port
								});
								await sock.opened;
								break;
							} else if (method === 'h' && hParam) {
								sock = await httpConnect(addr, port, skJson);
								break;
							}
						} catch { }
					}

					if (!sock) return;

					remote = sock;
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					const INITIAL_THRESHOLD = 6 * 1024 * 1024;
					let controlThreshold = INITIAL_THRESHOLD;
					let lastCount = 0;

					const reader = sock.readable.getReader();
					let totalBytes = 0;
					let sent = false;
					let writeQueue = Promise.resolve();

					(async () => {
						try {
							while (true) {
								const { done, value } = await reader.read();
								if (done) break;
								if (!value || !value.byteLength) continue;

								totalBytes += value.byteLength;

								// 回写数据队列控制
								writeQueue = writeQueue.then(() => {
									if (ws.readyState === 1) {
										if (!sent) {
											const combined = new Uint8Array(header.length + value.length);
											combined.set(header);
											combined.set(value, header.length);
											ws.send(combined);
											sent = true;
										} else {
											ws.send(value);
										}
									}
								});
								await writeQueue;

								// 控流逻辑开始
								const delta = totalBytes - lastCount;

								if (delta > controlThreshold) {
									// 网速提升，放行并增加阈值
									controlThreshold = delta;
								} else if (delta > INITIAL_THRESHOLD) {
									// 网速低于当前阈值，控流并回退（最低不小于初始值）
									await new Promise(r => setTimeout(r, 100 + Math.random() * 200));
									controlThreshold = controlThreshold - 2 * 1024 * 1024;
									if (controlThreshold < INITIAL_THRESHOLD) {
										controlThreshold = INITIAL_THRESHOLD;
									}
								}
								lastCount = totalBytes;
							}
						} catch (_) {
							// 可选：console.error('WS回传出错', _);
						} finally {
							try { reader.releaseLock(); } catch { }
							if (ws.readyState === 1) ws.close();
						}
					})();

				}

			})).catch(() => { });

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		return new Response("Hello World", { status: 200 });
	}
};

const SK_CACHE = new Map();

/**
 * 从路径中解析 SOCKS/HTTP 代理配置信息
 * @param {string} path - 代理配置路径字符串
 * @returns {{user: (string|null), pass: (string|null), host: string, port: number}} - 配置对象
 */
function getSKJson(path) {

	const cached = SK_CACHE.get(path);
	if (cached) return cached;


	// 分离认证和服务器部分
	const hasAuth = path.includes('@');
	const [cred, server] = hasAuth ? path.split('@') : [null, path];
	// 解析认证信息（如果存在）
	const [user = null, pass = null] = hasAuth ? cred.split(':') : [null, null];
	const [host, port = 443] = server.split(':');
	const result = {
		user,
		pass,
		host,
		port: +port
	};

	SK_CACHE.set(path, result);
	return result;
}

// SOCKS5连接
async function sConnect(targetHost, targetPort, skJson) {
	const sock = connect({
		hostname: skJson.host,
		port: skJson.port
	});
	await sock.opened;
	const w = sock.writable.getWriter();
	const r = sock.readable.getReader();
	await w.write(new Uint8Array([5, 2, 0, 2]));
	const auth = (await r.read()).value;
	if (auth[1] === 2 && skJson.user) {
		const user = te.encode(skJson.user);
		const pass = te.encode(skJson.pass);
		await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
		await r.read();
	}
	const domain = te.encode(targetHost);
	await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8,
		targetPort & 0xff
	]));
	await r.read();
	w.releaseLock();
	r.releaseLock();
	return sock;
};

// HTTP CONNECT代理连接
async function httpConnect(addressRemote, portRemote, skJson) {
	const { user, pass, host, port } = skJson;
	const sock = await connect({
		hostname: host,
		port: port
	});

	const connectRequest = buildConnectRequest(addressRemote, portRemote, user, pass);
	try {
		// 发送连接请求
		const writer = sock.writable.getWriter();
		await writer.write(te.encode(connectRequest));
		writer.releaseLock();
	} catch (err) {
		console.error('发送HTTP CONNECT请求失败:', err);
		throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
	}

	// 读取HTTP响应
	const reader = sock.readable.getReader();
	let respText = '';
	let connected = false;
	let responseBuffer = new Uint8Array(0);

	try {
		while (true) {
			const { value, done } = await reader.read();
			if (done) {
				console.error('HTTP代理连接中断');
				throw new Error('HTTP代理连接中断');
			}

			// 合并接收到的数据
			const newBuffer = new Uint8Array(responseBuffer.length + value.length);
			newBuffer.set(responseBuffer);
			newBuffer.set(value, responseBuffer.length);
			responseBuffer = newBuffer;

			// 将收到的数据转换为文本
			respText = new TextDecoder().decode(responseBuffer);

			// 检查是否收到完整的HTTP响应头
			if (respText.includes('\r\n\r\n')) {
				// 分离HTTP头和可能的数据部分
				const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
				const headers = respText.substring(0, headersEndPos);

				// 检查响应状态
				if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
					connected = true;

					// 如果响应头之后还有数据，我们需要保存这些数据以便后续处理
					if (headersEndPos < responseBuffer.length) {
						const remainingData = responseBuffer.slice(headersEndPos);
						// 创建一个缓冲区来存储这些数据，以便稍后使用
						const dataStream = new ReadableStream({
							start(controller) {
								controller.enqueue(remainingData);
							}
						});

						// 创建一个新的TransformStream来处理额外数据
						const { readable, writable } = new TransformStream();
						dataStream.pipeTo(writable).catch(err => console.error('处理剩余数据错误:', err));

						// 替换原始readable流
						// @ts-ignore
						sock.readable = readable;
					}
				} else {
					const errorMsg = `HTTP代理连接失败: ${headers.split('\r\n')[0]}`;
					console.error(errorMsg);
					throw new Error(errorMsg);
				}
				break;
			}
		}
	} catch (err) {
		reader.releaseLock();
		throw new Error(`处理HTTP代理响应失败: ${err.message}`);
	}

	reader.releaseLock();

	if (!connected) {
		throw new Error('HTTP代理连接失败: 未收到成功响应');
	}

	return sock;
}

// 构建CONNECT请求
function buildConnectRequest(address, port, username, password) {
	const headers = [
		`CONNECT ${address}:${port} HTTP/1.1`,
		`Host: ${address}:${port}`
	];

	if (username && password) {
		const base64Auth = btoa(`${username}:${password}`);
		headers.push(`Proxy-Authorization: Basic ${base64Auth}`);
	}

	headers.push(
		'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
		'Proxy-Connection: Keep-Alive',
		'Connection: Keep-Alive',
		'' // 最后的空行
	);

	return headers.join('\r\n') + '\r\n';
}
