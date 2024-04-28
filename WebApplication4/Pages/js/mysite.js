function sign() {
    var messageToSign = $("message").text;
    $.ajax({
        url: '/api/dataEncryption/sign-message',
        method: 'post',
        data: { message: messageToSign },
        success: function (result) {
            var textBox = $("signedMessage");
            textBox.text = result.data;
        }
    });
}

function verify() {

}

function generateRandom() {

}

function getPublicKey() {

}

function verifyWithPublic() {

}