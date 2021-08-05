package global

import "go.mongodb.org/mongo-driver/bson/primitive"

var NilUser User

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Username string             `bson:"username,omitempty"`
	Password string             `bson:"password,omitempty"`
}
