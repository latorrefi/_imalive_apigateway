var mongoose = require('mongoose');

var Schema = mongoose.Schema;
var ObjectId = Schema.Types.ObjectId;

var usersSchema = new Schema({
    _id:{ type:ObjectId, default: mongoose.Types.ObjectId },
    usernumber:Number,
    password:String,
    mail:String,
    roles: [ String ]
});


var Users = mongoose.model('Users', usersSchema,'users');

//compile schema to model
module.exports = {
    Users: Users
}

