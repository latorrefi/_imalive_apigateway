var passwordLength = 8;
var validContentType = ["application/json"]
module.exports = 
{

isValid : function (user){
    var isValid = true;
    var password = user.password;
    if(typeof password === 'undefined'){
        isValid = false;
    }else{
        if( password.length > passwordLength){
            isValid = false;
        }
    }
    var email = user.mail;
    if(typeof email === 'undefined'){
        isValid = false;
    }else{
        if(email.indexOf('@')===-1){
            isValid = false;
        }
    }
    return isValid;
},

isValidContentType : function (contentType){
    var isValid = true;
    if(validContentType.indexOf(contentType)===-1){
        isValid = false;
    }
    return isValid;
},

isPasswordValid : function (user){
    var isValid = true;
    var password = user.password;
    if( password.length > passwordLength){
        isValid = false;
    }
    return isValid;
},
isMailValid : function (user){
    var isValid = true;
    var email = user.mail;
    if(email.indexOf('@')===-1){
            isValid = false;
    }
    return isValid;
}
};