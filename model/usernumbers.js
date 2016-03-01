var mongoose = require('mongoose');

var Schema = mongoose.Schema;
var ObjectId = Schema.Types.ObjectId;

var userNumbersSchema = new Schema({
    _id:{ type:ObjectId, default: mongoose.Types.ObjectId },
    usernumber:Number
});

//compile schema to model
var UserNumbers = mongoose.model('UserNumbers', userNumbersSchema,'usernumbers');

module.exports = {
    UserNumbers: UserNumbers
}