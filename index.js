import express from "express";
import List from "./models/List.js";
import Task from "./models/Task.js";
import User from "./models/User.js";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT;

// Middleware

app.use(bodyParser.json());
app.use(function (req, res, next) {
    res.header(
        "Access-Control-Allow-Origin",
        "*"
    );
    res.header(
        "Access-Control-Allow-Methods",
        "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE"
    );
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id"
    );
    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );
    next();
})

let authenticate = (req, res, next) => {
    let token = req.header('x-access-token');

    jwt.verify(token, User.getJWTSecret(), (err, decoded) => {
        if (err) {
            res.status(401).send(err);
        } else {
            req.user_id = decoded._id;
            next();
        }
    });
}

let verifySession = (req, res, next) => {
    let refreshToken = req.header('x-refresh-token');
    let _id = req.header('_id');

    User.findByIdAndToken(_id, refreshToken).then((user) => {
        if (!user) {
            return Promise.reject({
                'error': 'User not found. Make sure that the refresh token and user id are correct'
            });
        }
        req.user_id = user._id;
        req.userObject = user;
        req.refreshToken = refreshToken;

        let isSessionValid = false;
        user.sessions.forEach((session) => {
            if (session.token === refreshToken) {
                if (User.hasRefreshTokenExpired(session.expiresAt) === false) {
                    isSessionValid = true;
                }
            }
        });
        if (isSessionValid) {
            next();
        } else {
            return Promise.reject({
                'error': 'Refresh token has expired or the session is invalid'
            })
        }
    }).catch((e) => {
        res.status(401).send(e);
    })
}

let deleteTasksFromList = (_listId) => {
    Task.deleteMany({
        _listId
    });
}

/* Routes */

// Lists
app.get('/lists', authenticate, async (req, res) => {
    await List.find({
        _userId: req.user_id
    }).then((lists) => {
        res.send(lists);
    }).catch((e) => {
        res.send(e);
    });
});

app.post('/lists', authenticate, async (req, res) => {
    let newList = new List({
        title: req.body.title,
        _userId: req.user_id,
    });
    await newList.save();
    res.status(201).json(newList);
});

app.patch('/lists/:id', authenticate, async (req, res) => {
    const list = await List.findOneAndUpdate({
        _id: req.params.id,
        _userId: req.user_id,
    }, {
        $set: req.body
    });
    res.status(200).json(list);
});

app.delete('/lists/:id', authenticate, async (req, res) => {
    const removedList = await List.findOneAndDelete(
        {
            _id: req.params.id,
            _userId: req.user_id,
        });
    deleteTasksFromList(removedList._id);
    res.status(200).json(removedList);
});

// Tasks

app.get('/lists/:listId/tasks', authenticate, async (req, res) => {
    const tasks = await Task.find({ _listId: req.params.listId });
    res.status(200).send(tasks);
});

app.post('/lists/:listId/tasks', authenticate, async (req, res) => {
    await List.findOne({
        _id: req.params.listId,
        _userId: req.user_id,
    }).then((user) => {
        if (user) {
            return true;
        } else {
            return false;
        }
    }).then(async (canCreateTask) => {
        if (canCreateTask) {
            let newTask = new Task({
                title: req.body.title,
                _listId: req.params.listId
            });
            await newTask.save();
            res.status(201).json(newTask);
        } else {
            res.sendStatus(404);
        }
    });
});

app.patch('/lists/:listId/tasks/:taskId', authenticate, async (req, res) => {
    await List.findOne({
        _id: req.params.listId,
        _userId: req.user_id,
    }).then((list) => {
        if (list) {
            return true;
        } else {
            return false;
        }
    }).then(async (canUpdateTasks) => {
        if (canUpdateTasks) {
            const task = await Task.findOneAndUpdate(
                {
                    _id: req.params.taskId,
                    _listId: req.params.listId
                }, {
                $set: req.body
            });
            res.send({ message: "Updated successfully" });
        } else {
            res.sendStatus(404);
        }
    });
});

app.delete('/lists/:listId/tasks/:taskId', authenticate, async (req, res) => {
    await List.findOne({
        _id: req.params.listId,
        _userId: req.user_id,
    }).then((list) => {
        if (list) {
            return true;
        } else {
            return false;
        }
    }).then(async (canDeleteTasks) => {
        if (canDeleteTasks) {
            const removedTask = await Task.findOneAndDelete(
                {
                    _id: req.params.taskId,
                    _listId: req.params.listId
                });
            res.status(200).json(removedTask);
        } else {
            res.sendStatus(404);
        }
    });
});

// User Routes

app.post('/users', (req, res) => {
    // Sign up
    let body = req.body;
    let newUser = new User(body);

    newUser.save().then(() => {
        return newUser.createSession();
    }).then((refreshToken) => {
        return newUser.generateAccessAuthToken().then((accessToken) => {
            return { accessToken, refreshToken }
        });
    }).then((authTokens) => {
        res.header('x-refresh-token', authTokens.refreshToken)
            .header('x-access-token', authTokens.accessToken)
            .send(newUser);
    }).catch((e) => {
        res.status(400).send(e);
    })
})

app.post('/users/login', (req, res) => {
    // Log in
    let email = req.body.email;
    let password = req.body.password;

    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
            return user.generateAccessAuthToken().then((accessToken) => {
                return { accessToken, refreshToken }
            });
        }).then((authTokens) => {
            res.header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user);
        })
    }).catch((e) => {
        res.status(400).send(e);
    });
})

app.get('/users/me/access-token', verifySession, (req, res) => {
    req.userObject.generateAccessAuthToken().then((accessToken) => {
        res.header('x-access-token', accessToken).send({ accessToken });
    }).catch((e) => {
        res.status(400).send(e);
    });
})

mongoose
    .connect(process.env.DB_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => {
        app.listen(PORT, () =>
            console.log(`Server listening`)
        );
    }).catch((error) =>
        console.log(`${error} did not connect`)
    );
