package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"reflect"
	"strconv"
	"strings"
	"time"

	"example.com/m/global"
	"example.com/m/serverpb"
	"github.com/dgrijalva/jwt-go"
	"github.com/elastic/go-elasticsearch/esapi"
	"github.com/go-redis/cache/v8"

	//"github.com/gofiber/fiber"
	"github.com/tealeg/xlsx"
	"github.com/vigneshuvi/GoDateFormat"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	//"golang.org/x/crypto/bcrypt"
)

type server struct {
	serverpb.UnimplementedServerServiceServer
}

const keySecret = "thteam"

func valid(authorization []string) bool {
	if len(authorization) < 1 {
		return false
	}
	token := strings.TrimPrefix(authorization[0], "Bearer ")
	// If you have more than one client then you will have to update this line.
	return Verify(token)
}
func Verify(accessToken string) bool {
	_, err := jwt.ParseWithClaims(accessToken, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("un")
		}
		return []byte(keySecret), nil
	},
	)
	if err != nil {
		return false
	}
	return true
}
func (s *server) Login(ctx context.Context, req *serverpb.LoginServer) (*serverpb.ResultLogin, error) {
	username, password := req.GetUsername(), req.GetPassword()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user global.User
	global.DB.Collection("user").FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if user == global.NilUser {
		resp := &serverpb.ResultLogin{
			Ok:          false,
			AccessToken: "",
		}
		return resp, errors.New("User not found")
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		resp := &serverpb.ResultLogin{
			Ok:          false,
			AccessToken: "",
		}
		return resp, errors.New("Incorrect password")
	}

	claim := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    user.ID.Hex(),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), //1 day
	})
	token, err := claim.SignedString([]byte(keySecret))
	if err != nil {
		resp := &serverpb.ResultLogin{
			Ok:          false,
			AccessToken: "",
		}
		return resp, errors.New("Could not login")
	}
	collection := global.DB.Collection("server")
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	if cur != nil {
		for cur.Next(context.TODO()) {
			var elem global.InfoServer
			er := cur.Decode(&elem)
			if er != nil {
				log.Fatal(err)
			}
			id := elem.ID
			filter := bson.M{"_id": id}
			update := bson.M{"$set": bson.M{
				"login": "true",
			}}
			_, err := global.DB.Collection("server").UpdateOne(context.TODO(), filter, update)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	resp := &serverpb.ResultLogin{
		Ok:          true,
		AccessToken: token,
	}
	return resp, nil
}
func (s *server) Logout(ctx context.Context, req *serverpb.Logout) (*serverpb.MessResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	collection := global.DB.Collection("server")
	cur, err := collection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	if cur != nil {
		for cur.Next(context.TODO()) {
			var elem global.InfoServer
			er := cur.Decode(&elem)
			if er != nil {
				log.Fatal(err)
			}
			id := elem.ID
			filter := bson.M{"_id": id}
			update := bson.M{"$set": bson.M{
				"login": "false",
			}}
			_, err := global.DB.Collection("server").UpdateOne(context.TODO(), filter, update)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	return &serverpb.MessResponse{
		Mess: "Done",
	}, nil
}
func (s *server) Index(ctx context.Context, req *serverpb.PaginationRequest) (*serverpb.ListServer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	var limit int64 = req.GetLimitPage()
	var page int64 = req.GetNumberPage()

	key := "index_" + strconv.FormatInt(limit, 10) + "_" + strconv.FormatInt(page, 10)
	var dt []*serverpb.Server
	data := global.MyRediscache.Get(ctx, key, &dt)
	if data == nil {
		return &serverpb.ListServer{
			Data: dt,
		}, nil
	} else {
		collection := global.DB.Collection("server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		findOptions := options.Find()
		if page == 1 {
			findOptions.SetSkip(0)
			findOptions.SetLimit(limit)
		} else {
			findOptions.SetSkip((page - 1) * limit)
			findOptions.SetLimit(limit)
		}

		cur, err := collection.Find(ctx, bson.M{}, findOptions)
		if err != nil {
			log.Fatal(err)
		}
		var st []global.InfoServer
		for cur.Next(context.TODO()) {
			// create a value into which the single document can be decoded
			var elem global.InfoServer
			er := cur.Decode(&elem)
			if er != nil {
				log.Fatal(err)
			}
			st = append(st, elem)
		}

		for _, v := range st {
			dt = append(dt, &serverpb.Server{
				IdServer:   v.ID.Hex(),
				Username:   v.Username,
				ServerName: v.ServerName,
				Ip:         v.Ip,
				Password:   v.Password,
			})
		}
	}

	if err := global.MyRediscache.Set(&cache.Item{
		Ctx:   ctx,
		Key:   key,
		Value: dt,
		TTL:   time.Minute,
	}); err != nil {
		panic(err)
	}

	resp := &serverpb.ListServer{
		Data: dt,
	}
	return resp, nil
}
func (s *server) AddServer(ctx context.Context, req *serverpb.Server) (*serverpb.ResponseServer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}

	var listStatus []global.StatusDetail
	listStatus = append(listStatus, global.StatusDetail{
		Status: "On",
		Time:   time.Now(),
	},
	)
	infoSv := global.InfoServer{
		ID:         [12]byte{},
		Username:   req.GetUsername(),
		Password:   string(req.GetPassword()),
		ServerName: req.GetServerName(),
		Ip:         req.GetIp(),
		Login:      "true",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	insertResult, err := global.DB.Collection("server").InsertOne(ctx, infoSv)
	if err != nil {
		panic(err)
	}
	//elasticsearch

	str := fmt.Sprintf("%v", insertResult.InsertedID)
	idResp := strings.Split(str, "\"")

	info := &global.ListStatus{
		ChangeStatus: listStatus,
	}
	//res, err := global.DBels.Info()
	dataJSON, err := json.Marshal(info)
	//js := string(dataJSON)
	//defer wg.Done()
	res := esapi.IndexRequest{
		Index:      "server-elas",
		DocumentID: idResp[1],
		Body:       strings.NewReader(string(dataJSON)),
	}
	res.Do(context.Background(), &global.DBels)

	resp := &serverpb.ResponseServer{
		IdServer: idResp[1],
		Data: &serverpb.Server{
			Username:   infoSv.Username,
			ServerName: infoSv.ServerName,
			Password:   infoSv.Password,
			Ip:         infoSv.Ip,
		},
	}
	return resp, nil
}
func (s *server) UpdateServer(ctx context.Context, req *serverpb.UpdateRequest) (*serverpb.ResponseServer, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{
		"username":   req.GetInfoServer().GetUsername(),
		"ip":         req.GetInfoServer().GetIp(),
		"servername": req.GetInfoServer().GetServerName(),
		//"updated_at": time.Now().String(),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := global.DB.Collection("server").UpdateOne(ctx, filter, update)
	if err != nil {
		log.Fatal(err)
	}
	resp := &serverpb.ResponseServer{
		IdServer: req.GetIdServer(),
		Data: &serverpb.Server{
			Username:   req.GetInfoServer().GetUsername(),
			ServerName: req.GetInfoServer().GetServerName(),
			Ip:         req.GetInfoServer().GetIp(),
		},
	}

	return resp, nil
}
func (s *server) DetailsServer(ctx context.Context, req *serverpb.DetailsServer) (*serverpb.DetailsServerResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	//filter := bson.M{"_id": req.GetIdServer()}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	keyList := "details_statusList_" + id.Hex()
	keyStatus := "details_status_" + id.Hex()
	var statusList []*serverpb.StatusDetail
	var statusServer string
	var detailSV global.ListStatus
	dataList := global.MyRediscache.Get(ctx, keyList, &statusList)
	dataStatus := global.MyRediscache.Get(ctx, keyStatus, &statusServer)
	if dataList != nil {
		//search
		var r map[string]interface{}
		var buf bytes.Buffer
		query := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": id,
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Fatalf("Error encoding query: %s", err)
		}

		res, err := global.DBels.Search(
			global.DBels.Search.WithContext(context.Background()),
			global.DBels.Search.WithIndex("server-elas"),
			global.DBels.Search.WithBody(&buf),
			global.DBels.Search.WithTrackTotalHits(true),
			global.DBels.Search.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		defer res.Body.Close()
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			log.Fatalf("Error parsing the response body: %s", err)
		}

		for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
			m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
			err := json.Unmarshal(m, &detailSV)
			if err != nil {
				log.Fatalf("Error getting response: %s", err)
			}
		}

		var startReq string
		if req.GetTimeIn() == "" {
			startReq = detailSV.ChangeStatus[0].Time.String()
		} else {
			startReq = req.GetTimeIn()
		}
		var endReq string

		if req.GetTimeOut() == "" {
			endReq = time.Now().String()
		} else {
			endReq = req.GetTimeOut()
		}
		start, err := time.Parse(time.RFC3339Nano, startReq)
		end, err := time.Parse(time.RFC3339Nano, endReq)
		if err != nil {
			log.Fatalf("error")
		}
		if start.Before(detailSV.ChangeStatus[0].Time) == true {
			statusList = append(statusList, &serverpb.StatusDetail{
				StatusDt: "Off",
				Time:     start.String(),
			})
		}
		for i := 0; i < len(detailSV.ChangeStatus); i++ {
			tmp := detailSV.ChangeStatus[i].Time
			if tmp.Before(start) && detailSV.ChangeStatus[i+1].Time.After(start) {
				statusList = append(statusList, &serverpb.StatusDetail{
					StatusDt: detailSV.ChangeStatus[i].Status,
					Time:     start.String(),
				})
			}
			if tmp.After(start) && tmp.Before(end) || tmp == start || tmp == end {
				statusList = append(statusList, &serverpb.StatusDetail{
					StatusDt: detailSV.ChangeStatus[i].Status,
					Time:     detailSV.ChangeStatus[i].Time.String(),
				})
			}
			if tmp.Before(detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Time) {
				if tmp.Before(end) && detailSV.ChangeStatus[i+1].Time.After(end) {
					statusList = append(statusList, &serverpb.StatusDetail{
						StatusDt: detailSV.ChangeStatus[i].Status,
						Time:     end.String(),
					})
				}
			}

		}
		if end.After(detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Time) == true {
			statusList = append(statusList, &serverpb.StatusDetail{
				StatusDt: detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status,
				Time:     end.String(),
			})
		}
		if err := global.MyRediscache.Set(&cache.Item{
			Ctx:   ctx,
			Key:   keyList,
			Value: statusList,
			TTL:   time.Minute,
		}); err != nil {
			panic(err)
		}
	}
	if dataStatus != nil {
		statusServer = detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status
		if err := global.MyRediscache.Set(&cache.Item{
			Ctx:   ctx,
			Key:   keyStatus,
			Value: statusServer,
			TTL:   time.Minute,
		}); err != nil {
			panic(err)
		}
	}
	resp := &serverpb.DetailsServerResponse{
		StatusServer: statusServer,
		Status:       statusList,
	}
	return resp, nil
}
func (s *server) Export(ctx context.Context, req *serverpb.ExportRequest) (*serverpb.ExportResponse, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	file := xlsx.NewFile()
	date := time.Now().Format(GoDateFormat.ConvertFormat("yyyy-MMM-dd"))
	sheet, _ := file.AddSheet("ServerManagement")
	row := sheet.AddRow()
	colName := [5]string{"Server name", "Username", "Password", "Ip", "Status"}
	for i := 0; i < len(colName); i++ {
		cell := row.AddCell()
		cell.Value = colName[i]
	}
	collection := global.DB.Collection("server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cur *mongo.Cursor
	var err error
	if req.GetPage() == false {
		cur, err = collection.Find(ctx, bson.M{})
	} else {
		page := req.GetNumberPage()
		limit := req.GetLimitPage()
		findOptions := options.Find()
		if page == 1 {
			findOptions.SetSkip(0)
			findOptions.SetLimit(limit)
		} else {
			findOptions.SetSkip((page - 1) * limit)
			findOptions.SetLimit(limit)
		}
		cur, err = collection.Find(ctx, bson.M{}, findOptions)
	}
	if err != nil {
		log.Fatal(err)
	}
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		row = sheet.AddRow()
		var elem global.InfoServer
		er := cur.Decode(&elem)
		if er != nil {
			log.Fatal(err)
		}
		listStatus := ""
		//search
		var r map[string]interface{}
		var buf bytes.Buffer
		query := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": elem.ID.Hex(),
				},
			},
		}
		if err := json.NewEncoder(&buf).Encode(query); err != nil {
			log.Fatalf("Error encoding query: %s", err)
		}
		res, err := global.DBels.Search(
			global.DBels.Search.WithContext(context.Background()),
			global.DBels.Search.WithIndex("server-elas"),
			global.DBels.Search.WithBody(&buf),
			global.DBels.Search.WithTrackTotalHits(true),
			global.DBels.Search.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		defer res.Body.Close()
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			log.Fatalf("Error parsing the response body: %s", err)
		}
		var detailSV global.ListStatus
		for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
			m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
			err := json.Unmarshal(m, &detailSV)
			if err != nil {
				log.Fatalf("Error getting response: %s", err)
			}
		}
		for _, v := range detailSV.ChangeStatus {

			listStatus += v.Time.String() + ": " + v.Status + "\n"
		}
		result := [5]string{elem.ServerName, elem.Username, elem.Password, elem.Ip, listStatus}
		for i := 0; i < len(colName); i++ {
			cell := row.AddCell()
			cell.Value = result[i]
		}
	}
	fileName := "export/" + date + ".xlsx"
	err = file.Save(fileName)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	return &serverpb.ExportResponse{
		Url: fileName,
	}, nil
}
func (s *server) DeleteServer(ctx context.Context, req *serverpb.DelServer) (*serverpb.DeleteServerResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())

	result, err := global.DB.Collection("server").DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Fatal(err)
	}
	if result.DeletedCount == 0 {
		return &serverpb.DeleteServerResponse{
			Ok: false,
		}, errors.New("Id incorrect")
	}

	res := esapi.DeleteRequest{
		Index:      "server-elas",
		DocumentID: req.IdServer,
	}
	_, err = res.Do(context.Background(), &global.DBels)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	resp := &serverpb.DeleteServerResponse{
		Ok: true,
	}
	return resp, nil
}
func UpdateStatus() {
	for {
		collection := global.DB.Collection("server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := collection.Find(ctx, bson.M{})
		if err != nil {
			log.Fatal(err)
		}
		if cur != nil {
			for cur.Next(context.TODO()) {
				// create a value into which the single document can be decoded
				var elem global.InfoServer
				er := cur.Decode(&elem)
				if er != nil {
					log.Fatal(err)
				}
				//get list status
				var r map[string]interface{}
				var buf bytes.Buffer
				query := map[string]interface{}{
					"query": map[string]interface{}{
						"match": map[string]interface{}{
							"_id": elem.ID.Hex(),
						},
					},
				}
				if err := json.NewEncoder(&buf).Encode(query); err != nil {
					log.Fatalf("Error encoding query: %s", err)
				}
				res, err := global.DBels.Search(
					global.DBels.Search.WithContext(context.Background()),
					global.DBels.Search.WithIndex("server-elas"),
					global.DBels.Search.WithBody(&buf),
					global.DBels.Search.WithTrackTotalHits(true),
					global.DBels.Search.WithPretty(),
				)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
				defer res.Body.Close()
				if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
					log.Fatalf("Error parsing the response body: %s", err)
				}
				var detailSV global.ListStatus
				for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
					m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
					err := json.Unmarshal(m, &detailSV)
					if err != nil {
						log.Fatalf("Error getting response: %s", err)
					}
				}

				dayChange := time.Now().Sub(elem.UpdatedAt).Hours() / 24
				if dayChange > 60 {
					if detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status != "Invalid" {
						detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
							Status: "Invalid",
							Time:   time.Now(),
						},
						)
						info := &global.ListStatus{
							ChangeStatus: detailSV.ChangeStatus,
						}
						var inInterface map[string]interface{}
						inrec, _ := json.Marshal(info)
						json.Unmarshal(inrec, &inInterface)
						var buf bytes.Buffer
						doc := map[string]interface{}{
							"query": map[string]interface{}{
								"match": map[string]interface{}{
									"_id": elem.ID.Hex(),
								},
							},
							"script": map[string]interface{}{
								"source": "ctx._source.changeStatus=params.changeStatus;",
								"params": inInterface,
							},
						}
						if err := json.NewEncoder(&buf).Encode(doc); err != nil {
							log.Fatalf("Error update: %s", err)
						}
						res, err := global.DBels.UpdateByQuery(
							[]string{"server-elas"},
							global.DBels.UpdateByQuery.WithBody(&buf),
							global.DBels.UpdateByQuery.WithContext(context.Background()),
							global.DBels.UpdateByQuery.WithPretty(),
						)
						if err != nil {
							log.Fatalf("Error update: %s", err)
						}
						defer res.Body.Close()
					}
				} else {
					if len(detailSV.ChangeStatus) > 0 {
						if elem.Login == "true" {
							if detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status == "Off" {
								detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
									Status: "On",
									Time:   time.Now(),
								},
								)
								info := &global.ListStatus{
									ChangeStatus: detailSV.ChangeStatus,
								}
								var inInterface map[string]interface{}
								inter, _ := json.Marshal(info)
								json.Unmarshal(inter, &inInterface)
								var buf bytes.Buffer
								doc := map[string]interface{}{
									"query": map[string]interface{}{
										"match": map[string]interface{}{
											"_id": elem.ID.Hex(),
										},
									},
									"script": map[string]interface{}{
										"source": "ctx._source.changeStatus=params.changeStatus;",
										"params": inInterface,
									},
								}
								if err := json.NewEncoder(&buf).Encode(doc); err != nil {
									log.Fatalf("Error update: %s", err)
								}
								res, err := global.DBels.UpdateByQuery(
									[]string{"server-elas"},
									global.DBels.UpdateByQuery.WithBody(&buf),
									global.DBels.UpdateByQuery.WithContext(context.Background()),
									global.DBels.UpdateByQuery.WithPretty(),
								)
								if err != nil {
									log.Fatalf("Error update: %s", err)
								}
								defer res.Body.Close()
							}
						} else {
							if detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status == "On" {
								detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
									Status: "Off",
									Time:   time.Now(),
								},
								)
								info := &global.ListStatus{
									ChangeStatus: detailSV.ChangeStatus,
								}
								var inInterface map[string]interface{}
								inter, _ := json.Marshal(info)
								json.Unmarshal(inter, &inInterface)
								var buf bytes.Buffer
								doc := map[string]interface{}{
									"query": map[string]interface{}{
										"match": map[string]interface{}{
											"_id": elem.ID.Hex(),
										},
									},
									"script": map[string]interface{}{
										"source": "ctx._source.changeStatus=params.changeStatus;",
										"params": inInterface,
									},
								}
								if err := json.NewEncoder(&buf).Encode(doc); err != nil {
									log.Fatalf("Error update: %s", err)
								}
								res, err := global.DBels.UpdateByQuery(
									[]string{"server-elas"},
									global.DBels.UpdateByQuery.WithBody(&buf),
									global.DBels.UpdateByQuery.WithContext(context.Background()),
									global.DBels.UpdateByQuery.WithPretty(),
								)
								if err != nil {
									log.Fatalf("Error update: %s", err)
								}
								defer res.Body.Close()
							}
						}
					}
				}

			}
		}
		time.Sleep(1 * time.Minute)
	}
}

func (s *server) ChangePassword(ctx context.Context, req *serverpb.ChangePasswordRequest) (*serverpb.MessResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	id, _ := primitive.ObjectIDFromHex(req.GetIdServer())
	filter := bson.M{"_id": id}
	var sv global.InfoServer
	global.DB.Collection("server").FindOne(ctx, bson.M{"_id": id}).Decode(&sv)
	var r map[string]interface{}
	var buf bytes.Buffer
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"_id": req.GetIdServer(),
			},
		},
	}
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		log.Fatalf("Error encoding query: %s", err)
	}
	res, err := global.DBels.Search(
		global.DBels.Search.WithContext(context.Background()),
		global.DBels.Search.WithIndex("server-elas"),
		global.DBels.Search.WithBody(&buf),
		global.DBels.Search.WithTrackTotalHits(true),
		global.DBels.Search.WithPretty(),
	)
	if err != nil {
		log.Fatalf("Error getting response: %s", err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		log.Fatalf("Error parsing the response body: %s", err)
	}
	var detailSV global.ListStatus
	for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
		m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
		err := json.Unmarshal(m, &detailSV)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
	}
	var update primitive.M
	if detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status == "Invalid" {
		var stUpdate string
		if sv.Login == "true" {
			stUpdate = "On"
		} else {
			stUpdate = "Off"
		}
		update = bson.M{"$set": bson.M{
			"password":   req.GetPassword(),
			"updated_at": time.Now(),
		}}
		detailSV.ChangeStatus = append(detailSV.ChangeStatus, global.StatusDetail{
			Status: stUpdate,
			Time:   time.Now(),
		},
		)
		info := &global.ListStatus{
			ChangeStatus: detailSV.ChangeStatus,
		}
		var inInterface map[string]interface{}
		inter, _ := json.Marshal(info)
		json.Unmarshal(inter, &inInterface)
		var buf bytes.Buffer
		doc := map[string]interface{}{
			"query": map[string]interface{}{
				"match": map[string]interface{}{
					"_id": req.GetIdServer(),
				},
			},
			"script": map[string]interface{}{
				"source": "ctx._source.changeStatus=params.changeStatus;",
				"params": inInterface,
			},
		}
		if err := json.NewEncoder(&buf).Encode(doc); err != nil {
			log.Fatalf("Error update: %s", err)
		}
		res, err := global.DBels.UpdateByQuery(
			[]string{"server-elas"},
			global.DBels.UpdateByQuery.WithBody(&buf),
			global.DBels.UpdateByQuery.WithContext(context.Background()),
			global.DBels.UpdateByQuery.WithPretty(),
		)
		if err != nil {
			log.Fatalf("Error update: %s", err)
		}
		defer res.Body.Close()
	} else {
		update = bson.M{"$set": bson.M{
			"password":   req.GetPassword(),
			"updated_at": time.Now(),
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ret, err := global.DB.Collection("server").UpdateOne(ctx, filter, update)
	log.Fatalln(ret)
	if err != nil {
		log.Fatal(err)
	}
	resp := &serverpb.MessResponse{
		Mess: "Done",
	}

	return resp, nil
}
func SendMail(mail string) {
	email := mail
	// Sender data.
	from := "thaithteam47@gmail.com"
	password := "anhemtui123"
	// Receiver email address.
	to := []string{email}
	// smtp server configuration.
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)
	for {
		collection := global.DB.Collection("server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := collection.Find(ctx, bson.M{})
		if err != nil {
			log.Fatal(err)
		}
		result := ""
		for cur.Next(context.TODO()) {
			// create a value into which the single document can be decoded
			var elem global.InfoServer
			er := cur.Decode(&elem)
			if er != nil {
				log.Fatal(err)
			}
			var r map[string]interface{}
			var buf bytes.Buffer
			query := map[string]interface{}{
				"query": map[string]interface{}{
					"match": map[string]interface{}{
						"_id": elem.ID.Hex(),
					},
				},
			}
			if err := json.NewEncoder(&buf).Encode(query); err != nil {
				log.Fatalf("Error encoding query: %s", err)
			}
			res, err := global.DBels.Search(
				global.DBels.Search.WithContext(context.Background()),
				global.DBels.Search.WithIndex("server-elas"),
				global.DBels.Search.WithBody(&buf),
				global.DBels.Search.WithTrackTotalHits(true),
				global.DBels.Search.WithPretty(),
			)
			if err != nil {
				log.Fatalf("Error getting response: %s", err)
			}
			defer res.Body.Close()
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error parsing the response body: %s", err)
			}
			var detailSV global.ListStatus
			for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
				m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
				err := json.Unmarshal(m, &detailSV)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
			}
			if len(detailSV.ChangeStatus) > 0 {
				result += "Id: " + elem.ID.Hex() + ", Server name: " + elem.ServerName + ", Status: " + detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status + "\n"
			}
		}
		msg := []byte("To:" + email + "\r\n" +
			"Subject: Daily monitoring report of server status\r\n" +
			"\r\n" +
			result + "\r\n")

		err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, msg)
		if err != nil {
			log.Fatalf("Error getting response: %s", err)
		}
		time.Sleep(1 * time.Minute)
	}
}
func (s *server) CheckStatus(ctx context.Context, req *serverpb.CheckStatusRequest) (*serverpb.CheckStatusResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("No data request")
	}
	if !valid(md["authorization"]) {
		return nil, fmt.Errorf("no authorization")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := "checkStatus"
	var lsStatus []*serverpb.DataStatus
	if err := global.MyRediscache.Get(ctx, key, &lsStatus); err != nil {
		return nil, errors.New("error cache")
	}
	return &serverpb.CheckStatusResponse{
		ListStatus: lsStatus,
	}, nil

}
func UpdateStatusCache() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		key := "checkStatus"
		var lsStatus []*serverpb.DataStatus
		var lsCacheStatus []*serverpb.DataStatus
		if err := global.MyRediscache.Get(ctx, key, &lsCacheStatus); err != nil {
		} else {
			collection := global.DB.Collection("server")
			cur, err := collection.Find(ctx, bson.M{})
			if err != nil {
				log.Fatal(err)
			}
			for cur.Next(context.TODO()) {
				// create a value into which the single document can be decoded
				var elem global.InfoServer
				er := cur.Decode(&elem)
				if er != nil {
					log.Fatal(err)
				}
				var r map[string]interface{}
				var buf bytes.Buffer
				query := map[string]interface{}{
					"query": map[string]interface{}{
						"match": map[string]interface{}{
							"_id": elem.ID.Hex(),
						},
					},
				}
				if err := json.NewEncoder(&buf).Encode(query); err != nil {
					log.Fatalf("Error encoding query: %s", err)
				}
				res, err := global.DBels.Search(
					global.DBels.Search.WithContext(context.Background()),
					global.DBels.Search.WithIndex("server-elas"),
					global.DBels.Search.WithBody(&buf),
					global.DBels.Search.WithTrackTotalHits(true),
					global.DBels.Search.WithPretty(),
				)
				if err != nil {
					log.Fatalf("Error getting response: %s", err)
				}
				defer res.Body.Close()
				if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
					log.Fatalf("Error parsing the response body: %s", err)
				}
				var detailSV global.ListStatus
				for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {
					m, _ := json.Marshal(hit.(map[string]interface{})["_source"])
					err := json.Unmarshal(m, &detailSV)
					if err != nil {
						log.Fatalf("Error getting response: %s", err)
					}
				}
				lsStatus = append(lsStatus, &serverpb.DataStatus{
					IdServer:   elem.ID.Hex(),
					ServerName: elem.ServerName,
					Status:     detailSV.ChangeStatus[len(detailSV.ChangeStatus)-1].Status,
				})

			}

			check := reflect.DeepEqual(lsStatus, lsCacheStatus)
			if check == false {
				if err := global.MyRediscache.Set(&cache.Item{
					Ctx:   ctx,
					Key:   key,
					Value: lsStatus,
					TTL:   20 * time.Second,
				}); err != nil {
					panic(err)
				}
			}

		}
		time.Sleep(1 * time.Minute)
	}
}

func main() {
	for {
		//go SendMail("thteam47@gmail.com")
		go UpdateStatus()
		go UpdateStatusCache()
		lis, err := net.Listen("tcp", ":9090")
		if err != nil {
			log.Fatalf("err while create listen %v", err)
		}
		s := grpc.NewServer()
		serverpb.RegisterServerServiceServer(s, &server{})
		err = s.Serve(lis)
		if err != nil {
			log.Fatalf("err while server %v", err)
		}
	}
}
