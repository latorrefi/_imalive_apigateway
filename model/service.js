var mongoose = require('mongoose');

var Schema = mongoose.Schema;
var ObjectId = Schema.Types.ObjectId;

var serviceSchema = new Schema({
    _id:{ type:ObjectId, default: mongoose.Types.ObjectId },
    name: String,
    url: String,
    endpoints: [ new mongoose.Schema({
        type: String,
        url: String,
        path_builder : String
    }) ],
    authorizedRoles: [String ]
});


var Service = mongoose.model('Service', serviceSchema,'service');

//compile schema to model
module.exports = {
    Service: Service
}