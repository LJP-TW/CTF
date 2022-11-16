!(function () {process.__nexe = {"resources":{"./anode.js":[0,321847]}};
})();!(function () {"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.restoreFs = exports.shimFs = void 0;
let originalFsMethods = null;
let lazyRestoreFs = () => { };
// optional Win32 file namespace prefix followed by drive letter and colon
const windowsFullPathRegex = /^(\\{2}\?\\)?([a-zA-Z]):/;
const upcaseDriveLetter = (s) => s.replace(windowsFullPathRegex, (_match, ns, drive) => `${ns || ''}${drive.toUpperCase()}:`);
function shimFs(binary, fs = require('fs')) {
    if (originalFsMethods !== null) {
        return;
    }
    originalFsMethods = Object.assign({}, fs);
    const { blobPath, resources: manifest } = binary, { resourceStart, stat } = binary.layout, directories = {}, notAFile = '!@#$%^&*', isWin = process.platform.startsWith('win'), isString = (x) => typeof x === 'string' || x instanceof String, noop = () => { }, path = require('path'), winPath = isWin ? upcaseDriveLetter : (s) => s, baseDir = winPath(path.dirname(process.execPath));
    let log = (_) => true;
    let loggedManifest = false;
    if ((process.env.DEBUG || '').toLowerCase().includes('nexe:require')) {
        log = (text) => {
            setupManifest();
            if (!loggedManifest) {
                process.stderr.write('[nexe] - MANIFEST' + JSON.stringify(manifest, null, 4) + '\n');
                process.stderr.write('[nexe] - DIRECTORIES' + JSON.stringify(directories, null, 4) + '\n');
                loggedManifest = true;
            }
            return process.stderr.write('[nexe] - ' + text + '\n');
        };
    }
    const getKey = function getKey(filepath) {
        if (Buffer.isBuffer(filepath)) {
            filepath = filepath.toString();
        }
        if (!isString(filepath)) {
            return notAFile;
        }
        let key = path.resolve(baseDir, filepath);
        return winPath(key);
    };
    const statTime = function () {
        return {
            atime: new Date(stat.atime),
            mtime: new Date(stat.mtime),
            ctime: new Date(stat.ctime),
            birthtime: new Date(stat.birthtime),
        };
    };
    let BigInt;
    try {
        BigInt = eval('BigInt');
    }
    catch (ignored) { }
    const minBlocks = Math.max(Math.ceil(stat.blksize / 512), 1);
    const createStat = function (extensions, options) {
        const stat = Object.assign(new fs.Stats(), binary.layout.stat, statTime(), extensions);
        if ('size' in extensions) {
            //Assume non adjustable allocation size for file system
            stat.blocks = Math.ceil(stat.size / stat.blksize) * minBlocks;
        }
        if (options && options.bigint && typeof BigInt !== 'undefined') {
            for (const k in stat) {
                if (Object.prototype.hasOwnProperty.call(stat, k) && typeof stat[k] === 'number') {
                    stat[k] = BigInt(stat[k]);
                }
            }
        }
        return stat;
    };
    const ownStat = function (filepath, options) {
        setupManifest();
        const key = getKey(filepath);
        if (directories[key]) {
            let mode = binary.layout.stat.mode;
            mode |= fs.constants.S_IFDIR;
            mode &= ~fs.constants.S_IFREG;
            return createStat({ mode, size: 0 }, options);
        }
        if (manifest[key]) {
            return createStat({ size: manifest[key][1] }, options);
        }
    };
    const getStat = function (fn) {
        return function stat(filepath, options, callback) {
            let stat;
            if (typeof options === 'function') {
                callback = options;
                stat = ownStat(filepath, null);
            }
            else {
                stat = ownStat(filepath, options);
            }
            if (stat) {
                process.nextTick(() => {
                    callback(null, stat);
                });
            }
            else {
                return originalFsMethods[fn].apply(fs, arguments);
            }
        };
    };
    function makeLong(filepath) {
        return path._makeLong && path._makeLong(filepath);
    }
    function fileOpts(options) {
        return !options ? {} : isString(options) ? { encoding: options } : options;
    }
    let setupManifest = () => {
        Object.keys(manifest).forEach((filepath) => {
            const entry = manifest[filepath];
            const absolutePath = getKey(filepath);
            const longPath = makeLong(absolutePath);
            const normalizedPath = winPath(path.normalize(filepath));
            if (!manifest[absolutePath]) {
                manifest[absolutePath] = entry;
            }
            if (longPath && !manifest[longPath]) {
                manifest[longPath] = entry;
            }
            if (!manifest[normalizedPath]) {
                manifest[normalizedPath] = manifest[filepath];
            }
            let currentDir = path.dirname(absolutePath);
            let prevDir = absolutePath;
            while (currentDir !== prevDir) {
                directories[currentDir] = directories[currentDir] || {};
                directories[currentDir][path.basename(prevDir)] = true;
                const longDir = makeLong(currentDir);
                if (longDir && !directories[longDir]) {
                    directories[longDir] = directories[currentDir];
                }
                prevDir = currentDir;
                currentDir = path.dirname(currentDir);
            }
        });
        manifest[notAFile] = false;
        directories[notAFile] = false;
        setupManifest = noop;
    };
    //naive patches intended to work for most use cases
    const nfs = {
        existsSync: function existsSync(filepath) {
            setupManifest();
            const key = getKey(filepath);
            if (manifest[key] || directories[key]) {
                return true;
            }
            return originalFsMethods.existsSync.apply(fs, arguments);
        },
        realpath: function realpath(filepath, options, cb) {
            setupManifest();
            const key = getKey(filepath);
            if (isString(filepath) && (manifest[filepath] || manifest[key])) {
                return process.nextTick(() => cb(null, filepath));
            }
            return originalFsMethods.realpath.call(fs, filepath, options, cb);
        },
        realpathSync: function realpathSync(filepath, options) {
            setupManifest();
            const key = getKey(filepath);
            if (manifest[key]) {
                return filepath;
            }
            return originalFsMethods.realpathSync.call(fs, filepath, options);
        },
        readdir: function readdir(filepath, options, callback) {
            setupManifest();
            const dir = directories[getKey(filepath)];
            if (dir) {
                if ('function' === typeof options) {
                    callback = options;
                    options = { encoding: 'utf8' };
                }
                process.nextTick(() => callback(null, Object.keys(dir)));
            }
            else {
                return originalFsMethods.readdir.apply(fs, arguments);
            }
        },
        readdirSync: function readdirSync(filepath, options) {
            setupManifest();
            const dir = directories[getKey(filepath)];
            if (dir) {
                return Object.keys(dir);
            }
            return originalFsMethods.readdirSync.apply(fs, arguments);
        },
        readFile: function readFile(filepath, options, callback) {
            setupManifest();
            const entry = manifest[getKey(filepath)];
            if (!entry) {
                return originalFsMethods.readFile.apply(fs, arguments);
            }
            const [offset, length] = entry;
            const resourceOffset = resourceStart + offset;
            const encoding = fileOpts(options).encoding;
            callback = typeof options === 'function' ? options : callback;
            originalFsMethods.open(blobPath, 'r', function (err, fd) {
                if (err)
                    return callback(err, null);
                originalFsMethods.read(fd, Buffer.alloc(length), 0, length, resourceOffset, function (error, bytesRead, result) {
                    if (error) {
                        return originalFsMethods.close(fd, function () {
                            callback(error, null);
                        });
                    }
                    originalFsMethods.close(fd, function (err) {
                        if (err) {
                            return callback(err, result);
                        }
                        callback(err, encoding ? result.toString(encoding) : result);
                    });
                });
            });
        },
        createReadStream: function createReadStream(filepath, options) {
            setupManifest();
            const entry = manifest[getKey(filepath)];
            if (!entry) {
                return originalFsMethods.createReadStream.apply(fs, arguments);
            }
            const [offset, length] = entry;
            const resourceOffset = resourceStart + offset;
            const opts = fileOpts(options);
            return originalFsMethods.createReadStream(blobPath, Object.assign({}, opts, {
                start: resourceOffset,
                end: resourceOffset + length - 1,
            }));
        },
        readFileSync: function readFileSync(filepath, options) {
            setupManifest();
            const entry = manifest[getKey(filepath)];
            if (!entry) {
                return originalFsMethods.readFileSync.apply(fs, arguments);
            }
            const [offset, length] = entry;
            const resourceOffset = resourceStart + offset;
            const encoding = fileOpts(options).encoding;
            const fd = originalFsMethods.openSync(process.execPath, 'r');
            const result = Buffer.alloc(length);
            originalFsMethods.readSync(fd, result, 0, length, resourceOffset);
            originalFsMethods.closeSync(fd);
            return encoding ? result.toString(encoding) : result;
        },
        statSync: function statSync(filepath, options) {
            const stat = ownStat(filepath, options);
            if (stat) {
                return stat;
            }
            return originalFsMethods.statSync.apply(fs, arguments);
        },
        stat: getStat('stat'),
        lstat: getStat('lstat'),
        lstatSync: function statSync(filepath, options) {
            const stat = ownStat(filepath, options);
            if (stat) {
                return stat;
            }
            return originalFsMethods.lstatSync.apply(fs, arguments);
        },
    };
    if (typeof fs.exists === 'function') {
        nfs.exists = function (filepath, cb) {
            cb = cb || noop;
            const exists = nfs.existsSync(filepath);
            process.nextTick(() => cb(exists));
        };
    }
    const patches = process.nexe.patches || {};
    delete process.nexe;
    patches.internalModuleReadFile = function (original, ...args) {
        setupManifest();
        const filepath = getKey(args[0]);
        if (manifest[filepath]) {
            log('read     (hit)              ' + filepath);
            return nfs.readFileSync(filepath, 'utf-8');
        }
        log('read          (miss)       ' + filepath);
        return original.call(this, ...args);
    };
    let returningArray;
    patches.internalModuleReadJSON = function (original, ...args) {
        if (returningArray == null)
            returningArray = Array.isArray(original.call(this, ''));
        const res = patches.internalModuleReadFile.call(this, original, ...args);
        return returningArray && !Array.isArray(res)
            ? [res, /"(main|name|type|exports|imports)"/.test(res)]
            : res;
    };
    patches.internalModuleStat = function (original, ...args) {
        setupManifest();
        const filepath = getKey(args[0]);
        if (manifest[filepath]) {
            log('stat     (hit)              ' + filepath + '   ' + 0);
            return 0;
        }
        if (directories[filepath]) {
            log('stat dir (hit)              ' + filepath + '   ' + 1);
            return 1;
        }
        const res = original.call(this, ...args);
        if (res === 0) {
            log('stat          (miss)        ' + filepath + '   ' + res);
        }
        else if (res === 1) {
            log('stat dir      (miss)        ' + filepath + '   ' + res);
        }
        else {
            log('stat                 (fail) ' + filepath + '   ' + res);
        }
        return res;
    };
    if (typeof fs.exists === 'function') {
        nfs.exists = function (filepath, cb) {
            cb = cb || noop;
            const exists = nfs.existsSync(filepath);
            if (!exists) {
                return originalFsMethods.exists(filepath, cb);
            }
            process.nextTick(() => cb(exists));
        };
    }
    if (typeof fs.copyFile === 'function') {
        nfs.copyFile = function (filepath, dest, flags, callback) {
            setupManifest();
            const entry = manifest[getKey(filepath)];
            if (!entry) {
                return originalFsMethods.copyFile.apply(fs, arguments);
            }
            if (typeof flags === 'function') {
                callback = flags;
                flags = 0;
            }
            nfs.readFile(filepath, (err, buffer) => {
                if (err) {
                    return callback(err);
                }
                originalFsMethods.writeFile(dest, buffer, (err) => {
                    if (err) {
                        return callback(err);
                    }
                    callback(null);
                });
            });
        };
        nfs.copyFileSync = function (filepath, dest) {
            setupManifest();
            const entry = manifest[getKey(filepath)];
            if (!entry) {
                return originalFsMethods.copyFileSync.apply(fs, arguments);
            }
            return originalFsMethods.writeFileSync(dest, nfs.readFileSync(filepath));
        };
    }
    if (typeof fs.realpath.native === 'function') {
        nfs.realpath.native = function realpathNative(filepath, options, cb) {
            setupManifest();
            const key = getKey(filepath);
            if (isString(filepath) && (manifest[filepath] || manifest[key])) {
                return process.nextTick(() => cb(null, filepath));
            }
            return originalFsMethods.realpath.native.call(fs, filepath, options, cb);
        };
        nfs.realpathSync.native = function realpathSyncNative(filepath, options) {
            setupManifest();
            const key = getKey(filepath);
            if (manifest[key]) {
                return filepath;
            }
            return originalFsMethods.realpathSync.native.call(fs, filepath, options);
        };
    }
    Object.assign(fs, nfs);
    lazyRestoreFs = () => {
        Object.keys(nfs).forEach((key) => {
            fs[key] = originalFsMethods[key];
        });
        lazyRestoreFs = () => { };
    };
    return true;
}
exports.shimFs = shimFs;
function restoreFs() {
    lazyRestoreFs();
}
exports.restoreFs = restoreFs;

shimFs(process.__nexe)
})();!(function () {
    if (process.argv[1] && process.env.NODE_UNIQUE_ID) {
      const cluster = require('cluster')
      cluster._setupWorker()
      delete process.env.NODE_UNIQUE_ID
    }
  })();!(function () {
      if (!process.send) {
        const path = require('path')
        const entry = path.resolve(path.dirname(process.execPath),"./anode.js")
        process.argv.splice(1,0, entry)
      }
    })();;