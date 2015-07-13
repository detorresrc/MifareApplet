var MifareErrorCodes = {
    MF_CARD_EXCEPTION_ERROR      : 1000,
    MF_SUCCESS                   : 10001,
    MF_INVALID_KEY_SIZE          : 10002,
    MF_NO_READER_FOUND           : 10003,
    MF_NO_SUPPLIED_BUFFER        : 10004,
    MF_AUTH_SEND_ERROR           : 10005,
    MF_AUTH_ERROR                : 10006,
    MF_READ_BLOCK_ERROR          : 10007,
    MF_WRITE_BLOCK_ERROR         : 10008,
    MF_NO_CARD_FOUND             : 10009,
    MF_CARD_NOT_SUPPORTED        : 10010,
    MF_WRITE_INVALID_BUFFER_SIZE : 10011,
    MF_WRITE_MD5_ERROR           : 10012,
    MF_HASH_AUTH_ERROR           : 100013,
    MF_HASH_WRITE_ERROR          : 100014,
    MF_READ_UID_ERROR            : 100015,
    MF_READ_UID_NOT_SUPPORTED    : 100016,
    MF_READ_HASH_DATA_ERROR      : 100017,
    MF_READ_HASH_MISMATCH        : 100018,

    MF_API_ERROR                 : 999
}

MifareException = function(err_type){
    errTypeToMsg = function(err_type){
        msg = '';
        switch(parseInt(err_type)){
            case MifareErrorCodes.MF_CARD_EXCEPTION_ERROR:       msg = 'Card Exception Error'; break;
            case MifareErrorCodes.MF_SUCCESS:                    msg = 'Success'; break;
            case MifareErrorCodes.MF_INVALID_KEY_SIZE:           msg = 'Invalid key size'; break;
            case MifareErrorCodes.MF_NO_READER_FOUND:            msg = 'No reader found'; break;
            case MifareErrorCodes.MF_NO_SUPPLIED_BUFFER:         msg = 'No supplied buffer'; break;
            case MifareErrorCodes.MF_AUTH_SEND_ERROR:            msg = 'Can\'t send auth byte to reader'; break;
            case MifareErrorCodes.MF_AUTH_ERROR:                 msg = 'Auth error'; break;
            case MifareErrorCodes.MF_READ_BLOCK_ERROR:           msg = 'Can\'t read block'; break;
            case MifareErrorCodes.MF_WRITE_BLOCK_ERROR:          msg = 'Can\'t write data to block'; break;
            case MifareErrorCodes.MF_NO_CARD_FOUND:              msg = 'No card found'; break;
            case MifareErrorCodes.MF_CARD_NOT_SUPPORTED:         msg = 'Card is not supported'; break;
            case MifareErrorCodes.MF_WRITE_INVALID_BUFFER_SIZE:  msg = 'Invalid buffer size'; break;
            case MifareErrorCodes.MF_WRITE_MD5_ERROR:            msg = 'Can\'t write hash'; break;
            case MifareErrorCodes.MF_HASH_AUTH_ERROR:            msg = 'Hash Auth error'; break;
            case MifareErrorCodes.MF_HASH_WRITE_ERROR:           msg = 'Hash Write error'; break;
            case MifareErrorCodes.MF_READ_UID_ERROR:             msg = 'Can\'t get UID'; break;
            case MifareErrorCodes.MF_READ_UID_NOT_SUPPORTED:     msg = 'UID is not supported'; break;
            case MifareErrorCodes.MF_READ_HASH_DATA_ERROR:       msg = 'Can\'t read hash data'; break;
            case MifareErrorCodes.MF_READ_HASH_MISMATCH:         msg = 'Hash mismatch'; break;

            case MifareErrorCodes.MF_API_ERROR:                  msg = 'API error, please try again'; break;
            default : msg = err_type;
        }
        return msg;
    };

    return {
        name    : (err_type && err_type.type) ? err_type.type : 'MifareException',
        message : (err_type && err_type.message) ? err_type.message : errTypeToMsg(err_type)
    }
}

MifareAppletApi = function(){
    var applet = null;

    return {

        setApplet : function(app){
            applet = app;
        },

        resetCard : function(){
            console.log("MifareAppletApi::resetCard()");

            var ret = applet.ResetCard();
            console.log(ret);
            if( ret != MifareErrorCodes.MF_SUCCESS ){
                exc = new MifareException(ret);
                throw exc;
            }
        },

        initializeCard : function(){
            console.log("MifareAppletApi::initializeCard()");

            var ret = applet.InitilizeCard();
            console.log(ret);
            if( ret != MifareErrorCodes.MF_SUCCESS ){
                exc = new MifareException(ret);
                throw exc;
            }
        },

        read : function(elementId){
            console.log("MifareAppletApi::read()");

            var ret = jQuery.parseJSON( applet.ReadCard() );
            if( ret.code == MifareErrorCodes.MF_SUCCESS ){
                $("#" + elementId).val( ret.data );
            }else{
                exc = new MifareException(ret.code);
                throw exc;
            }
        },

        readWait : function(callback, secondsToWait){
            console.log("MifareAppletApi::readWait()");

            applet.CardPresent_Wait(
                callback,
                secondsToWait
            );
        },

        write : function(data){
            console.log("MifareAppletApi::write()");

            var ret = applet.WriteCard(data);
            console.log(ret);
            if( ret != MifareErrorCodes.MF_SUCCESS ){
                exc = new MifareException(ret);
                throw exc;
            }
            
        },

        writeWait : function(callback, secondsToWait){
            console.log("MifareAppletApi::writeWait()");

            applet.CardPresent_Wait(
                callback,
                secondsToWait
            );
        },

    }
}();