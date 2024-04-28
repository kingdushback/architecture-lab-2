function sign() {
    var messageToSign = $("#message").val();
    $.ajax({
        url: '/api/dataEncryption/sign-message?message='+messageToSign,
        method: 'post',
        success: function (result) {
            var textBox = $("#signedMessage");
            textBox.val(result);
        }
    });
}

function verify() {
    var messageSigned = $("#signedMessage").val();
    var messageToSign = $("#message").val();
    $.ajax({
        url: '/api/dataEncryption/verify-sign?message=' + messageToSign,
        method: 'post',
        data: {
            signedHash: messageSigned
        },
        success: function (result) {
            alert(result);
        },
        error: function(result){
            alert('The signature is invalid due to the wrong encryption');
        }
    });
}

function generateRandom() {
    $.ajax({
        url: '/api/dataEncryption/generate-random-message',
        method: 'get',
        success: function (result) {
            var items = JSON.parse(result);
            var textBox = $("#randomMessage");
            textBox.val(items['randomMessage']);
            var textBox = $("#randomMessageSigned");
            textBox.val(items['signedRandom']);
        },
        error: function (result) {
            alert('An error has occured');
        }
    });
}

function getPublicKey() {
    $.ajax({
        url: '/api/dataEncryption/get-public-key',
        method: 'get',
        success: function (result) {
            var textBox = $("#publicKey");
            textBox.val(result);
        },
        error: function (result) {
            alert('An error has occured');
        }
    });
}

function verifyWithPublic() {
    var messageSigned = $("#randomMessageSigned").val();
    var messageToSign = $("#randomMessage").val();
    var key = $("#publicKey").val();
    $.ajax({
        url: '/api/dataEncryption/verify-sign?message=' + messageToSign,
        method: 'post',
        data: {
            signedHash: messageSigned,
            pemKey: key
        },
        success: function (result) {
            alert(result);
        },
        error: function (result) {
            alert('The signature is invalid due to the wrong encryption');
        }
    });

}