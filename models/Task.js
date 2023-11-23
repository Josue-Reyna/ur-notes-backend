import mongoose from "mongoose";

const taskSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        minlength: 1,
        trim: true,
    },
    _listId:{
        type: mongoose.Types.ObjectId,
        required: true,
    },
    completed: {
        type: Boolean,
        default: false,
    }
});

const Task = mongoose.model('Task', taskSchema);

export default Task;