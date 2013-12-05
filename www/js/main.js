//main
var mEncrypted;

var app = {
    
    //SHA1: function (s) {
    //    var hash = CryptoJS.SHA1(s);
    //    return hash;
    //},

    hashPass: function (password, bits, callback) {
        console.log('Hashing: ' + password);
        var l = (bits / 8); //Eight bits per character
        var key = '';
        var hashed = '';

        for (var pass = 0; pass < 3; pass++) { //three passes
            console.log("pass: " + pass);
            hashed = '';
            while (hashed.length < l) {
                console.log("length: " + hashed.length);
                //toast("length: " + hashed.length);
                password = CryptoJS.SHA1(password); //sha1 hash
                //toast("after sha1");
                console.log("after sha1");
                password = password.toString(); //set password equal to hash and repeat
                password = password.toUpperCase(); //convert to upper case to match desktop version
                console.log("after to upper case");
                hashed = hashed + password;
                console.log("hashed: " + hashed);
            }
            if (hashed.length > l) {
                hashed = hashed.substring(0, l); //trim key to proper size
                console.log("Trimming");
            }
            password = hashed;
            console.log('Pass ' + (pass + 1) + ' ' + password);
        }
        
        console.log("after for loop");
        
        key = password; //set key to the thrice encoded password

        console.log("key a " + key);
        key = encode_utf8(key);
        console.log("key b " + key);
        //////console.log('UTF8: ' + key);

        console.log('Key: ' + key);
        console.log('Key length: ' + key.length);
        return key;
    },

    encryptAES: function (plaintext, password, test, callback) {
        console.log('AES in: ' + plaintext + ' ' + password);
        var ciphertext = '';
        if (plaintext !== undefined && password !== undefined) {
            console.log("after plaintext");
            var key = app.hashPass(password, 256); //generate 256 bit hash
            console.log("key: " + key);
            var nonce = '';
            var bits = 256;
            var iv = '9d9wjd982jh8fska'; //Init Vector


            key = encode_utf8(key);
            iv = encode_utf8(iv);

            key = CryptoJS.enc.Utf8.parse(key); // convert to word array
            if (test === false) {
                for (var i = 0; i < 15; i++) {
                    nonce += app.getLetter(); //Generate random nonce
                }
            } else {
                nonce = '123456781234567'; //Use this nonce for tests    
            }
            console.log("nonce: " + nonce);
            //TESTING:
            plaintext = plaintext + encode_utf8(nonce); //Add nonce to plaintext
            //plaintext = encode_utf8(plaintext);
            //////console.log('plaintext: ' + plaintext);

            //key = CryptoJS.enc.Hex.parse(key);
            iv = CryptoJS.enc.Utf8.parse(iv); //Ensure IV is in the proper format
            //ENCRYPT
            var encrypted = CryptoJS.AES.encrypt(plaintext, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.NoPadding
            });

            ciphertext = encrypted.toString();
        }
        console.log('AES out: ' + ciphertext);
        if (callback !== undefined) {
            //////console.log('callback');
            callback(ciphertext);
        } else {
            return ciphertext;
        }
    },

    decryptAES: function (ciphertext, password, callback) {
        //////console.log('AESD in: ' + ciphertext + ' ' + password);
        var plaintext = '';
        if (ciphertext !== undefined && password !== undefined) {


            var key = app.hashPass(password, 256); //generate 256 bit hash
            var bits = 256;
            var iv = '9d9wjd982jh8fska'; //Init Vector



            key = encode_utf8(key);
            iv = encode_utf8(iv);

            key = CryptoJS.enc.Utf8.parse(key); // convert to word array
            iv = CryptoJS.enc.Utf8.parse(iv);

            //DECRYPT
            var decrypted = CryptoJS.AES.decrypt(ciphertext, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.NoPadding
            });
            //////console.log(decrypted);
            plaintext = decrypted.toString(CryptoJS.enc.Latin1); //make readable
            //////console.log('latin1: ' + plaintext);
            plaintext = plaintext.substring(0, plaintext.length - 15); //remove nonce
            plaintext = decode_utf8(plaintext);
            //////console.log('AESD out: ' + plaintext);
        }

        if (callback !== undefined) {
            callback(plaintext);
        } else {
            return plaintext;
        }
    },

    encryptBlowfish: function (plaintext, password, test, callback) {
        var ciphertext = '';
        if (plaintext !== undefined && password !== undefined) {
            console.log('Blowfish in: ' + plaintext + ' ' + password);
            var key = app.hashPass(password, 448); //generate 256 bit hash
            var nonce = '';
            var bits = 448;


            key = encode_utf8(key);

            //key = CryptoJS.enc.Utf8.parse(key); // convert to word array
            /*if (test === false) {
                for (var i=0;i<15;i++) {
                    nonce += app.getLetter();  //Generate random nonce
                }    
            } else {
                nonce = '1234567812345678123';  //Use this nonce for tests    
            }*/

            nonce = app.getNonce(15, test);

            //TESTING:
            plaintext = encode_utf8(plaintext) + encode_utf8(nonce); //Add nonce to plaintext
            //plaintext = encode_utf8(plaintext);


            //ENCRYPT
            ////console.log(plaintext);
            var encrypted = blowfish.encrypt(plaintext, key, {
                cipherMode: 1,
                outputType: 0
            });

            ciphertext = encrypted;
        }
        console.log('Blowfish out: ' + ciphertext);
        if (callback !== undefined) {
            callback(ciphertext);
        } else {

            return ciphertext;
        }
    },

    decryptBlowfish: function (ciphertext, password, callback) {
        ////console.log('BlowfishD in: ' + ciphertext + ' ' + password);
        var plaintext = '';
        if (ciphertext !== undefined && password !== undefined) {
            var key = app.hashPass(password, 448); //generate 256 bit hash
            var bits = 448;
            //var iv = '9d9wjd982jh8fska';  //Init Vector


            key = encode_utf8(key);

            //key = CryptoJS.enc.Utf8.parse(key); // convert to word array
            //iv = CryptoJS.enc.Utf8.parse(iv);

            //DECRYPT
            ////console.log(key);
            //////console.log(iv);
            var decrypted = blowfish.decrypt(ciphertext, key, {
                cipherMode: 1,
                outputType: 0
            });
            plaintext = decrypted;
            plaintext = app.delNonce(plaintext);
            //plaintext = plaintext.substring(0, plaintext.length - 19);  //remove nonce
            plaintext = decode_utf8(plaintext);
            ////console.log('BlowfishD out: ' + plaintext);
        }
        if (callback !== undefined) {
            callback(plaintext);
        } else {
            return plaintext;
        }
    },

    getNonce: function (iLen, test) {
        var ret = '';
        var rnd = 0;
        for (var i = 0; i < iLen; i++) {
            if (test === true) {
                ret += String.fromCharCode(1);
            } else {
                rnd = Math.floor((Math.random() * (7)));
                ret += String.fromCharCode(rnd);
            }
        }
        ////console.log('Nonce: ' + ret);
        return ret;
    },

    delNonce: function (s) {
        ////console.log('nonce1: ' + s);
        s = s.replace(/[\x00-\x07]/g, '');
        ////console.log('nonce2: ' + s);
        return s;
    },

    initialize: function () {
        console.log('init');

        $('#btnTestB64Dec').on('click', function (e) {

            var $elTxtEncode = $('#txtEncode');
            var $elTxtEncoded = $('#txtEncoded');
            $elTxtEncoded.val(Base64.decode($elTxtEncode.val()));
        });

        $('#btnTestB64Enc').on('click', function (e) {
            var $elTxtEncode = $('#txtEncode');
            var $elTxtEncoded = $('#txtEncoded');
            $elTxtEncoded.val(Base64.encode($elTxtEncode.val()));
        });

        $('#btnTestEnc').on('click', function (e) {
            var $elTxtKey = $('#txtKey');
            var $elTxtEncode = $('#txtEncode');
            var $elTxtEncoded = $('#txtEncoded');
            var $elTxtDecoded = $('#txtDecoded');
            var $elSelEncryptionTest = $('#selEncryptionTest');
            $elTxtDecoded.val('');
            switch ($elSelEncryptionTest.val()) {
            case 'AES':
                app.encryptAES($elTxtEncode.val(), $elTxtKey.val(), true, function (encrypted) {
                    ////console.log('callback encrypted: ' + encrypted);
                    //mEncrypted = encrypted;
                    //encrypted = encrypted.hexEncode();
                    $elTxtEncoded.val(encrypted);
                    //toast(i18n.t('//toast.EncryptedAES')); //"Encrypted AES"
                });
                break;
            case 'Blowfish':
                app.encryptBlowfish($elTxtEncode.val(), $elTxtKey.val(), true, function (encrypted) {

                    //mEncrypted = encrypted;
                    //encrypted = encrypted.hexEncode();
                    $elTxtEncoded.val(encrypted); //already in base64 
                    //toast(i18n.t('//toast.encryptedBlowfish')); //"Encrypted Blowfish"
                });
                break;
            }
        });

        $('#btnTestDec').on('click', function (e) {
            var $elTxtKey = $('#txtKey');
            var $elTxtEncode = $('#txtEncode');
            var $elTxtEncoded = $('#txtEncoded');
            var $elTxtDecoded = $('#txtDecoded');
            var $elSelEncryptionTest = $('#selEncryptionTest');
            var desktopEnc = 'orTAohqcWNAT8zJGGBWUyDY3';
            //var toBeDecrypted = desktopEnc;
            var toBeDecryptedFromMem = mEncrypted;
            var toBeDecrypted = $elTxtEncoded.val();

            switch ($elSelEncryptionTest.val()) {
            case 'AES':
                app.decryptAES(toBeDecrypted, $elTxtKey.val(), function (decrypted) {
                    $elTxtDecoded.val(decrypted);
                    //toast(i18n.t('//toast.DecryptedAES')); //"Decrypted AES"
                });
                break;
            case 'Blowfish':
                app.decryptBlowfish(toBeDecrypted, $elTxtKey.val(), function (decrypted) {
                    $elTxtDecoded.val(decrypted);
                    //toast(i18n.t('//toast.DecryptedBlowfish')); //"Decrypted Blowfish"
                });
                break;
            }
        });

  
    },

 


};

app.initialize();