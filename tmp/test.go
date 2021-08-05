package main

import (
	"context"
	"fmt"

	"example.com/m/global"
	"go.mongodb.org/mongo-driver/bson"
)


func main() {
	fmt.Println("sdg")
	resp, err := global.DB.Collection("user").InsertOne(context.Background(),bson.M{
		"username": "us",
		//"servername": "sv2",
		//"ip": "24",
		"password": "35",
	})
	fmt.Println("dsg")
	fmt.Println(resp.InsertedID)
	fmt.Println(err)
}