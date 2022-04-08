package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const db = "goAdmin"
const col = "AdminDetails"

var client *mongo.Client

var jwtKey = []byte("secret") //to generate jwtkey

type Credentials struct { //struct for signin
	FirstName string `json:"firstname" bson:"firstname"` // mongo will take in bson formate but we will give in bson
	//bson == firstname should have same name for fetch in raw
	LastName string `json:"lastname" bson:"lastname"`
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
	OTP      string `json:"otp" bson:"otp"` //for forget password
}

// type DataDetails struct { //struct for login
// 	Email    string `json:"email" bson:"email"`
// 	Password string `json:"password" bson:"password"`
// }

type Claims struct { //struct to generate cookies & tooken
	Email string `json:"email"`
	jwt.StandardClaims
}

func main() {
	fmt.Println("Starting the application")
	r := mux.NewRouter() //instance of router

	//cors function starts
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH"},
		AllowCredentials: true,
		// AllowedHeaders:   []string{"*"},
		AllowedHeaders: []string{"accept", "authorization", "content-type"},

		// Enable Debugging for testing, consider disabling in production
		Debug: true,
	})

	handler := c.Handler(r)

	//cors function ends

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second) //time out with in this it shd work r show error

	client, _ = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017")) // to connect db

	r.HandleFunc("/post", UserSignup).Methods("POST") //replace r in place of http and write the method
	r.HandleFunc("/post/Login", UserLogin).Methods("POST")
	r.HandleFunc("/post/ChangePassword/chaging/password", PostChangePassword).Methods("POST")
	r.HandleFunc("/patch/ChangePassword/chaging/password", PatchChangePassword).Methods("PATCH")
	r.HandleFunc("/home/forgot", ForgotPassword).Methods("PATCH")
	r.HandleFunc("/get", getUser).Methods("GET") //replace r in place of http and write the method
	http.Handle("/", r)                          //use this router as default handler
	http.ListenAndServe("localhost:8080", handler)

}

// func getHash(pwd []byte) string { //pwd is input parameter and []byte iis datatype and return is in string
// 	hash, err := bcrypt.GenerateFromPassword(pwd,bcrypt.MinCost)
// 	if err != nil { //for error handling
// 		log.Println(err)
// 	}
// 	return string(hash)

// }

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

//for signup
func UserSignup(w http.ResponseWriter /* response to user */, r *http.Request /* request from user */) {
	w.Header().Set("Content-Type", "application/json")
	var user Credentials //it will take datatype like struct

	json.NewDecoder(r.Body).Decode(&user)
	fmt.Println(user)
	//password := user.Password
	user.Password = getHash([]byte(user.Password))
	collection := client.Database(db).Collection(col) // the data will passed to the datatype
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	result, _ := collection.InsertOne(ctx, user) // the data will be passed one by one
	json.NewEncoder(w).Encode(result)            //response is given

}

//for login
func UserLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var details Credentials //user entered details

	var dbDetails Credentials                //database stored details and we have to compare both
	json.NewDecoder(r.Body).Decode(&details) //storing all details (givinen by users in details) and storing in var called compare
	fmt.Println(details)
	collection := client.Database(db).Collection(col) //connection to db
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	compare := collection.FindOne(ctx, bson.M{"email": details.Email}).Decode(&dbDetails) // we are comparing details.Email is user entered email with dbDetails database email
	if compare != nil {                                                                   // if data is not matched it shows error
		w.WriteHeader(http.StatusBadRequest) //w.writeHeader is response ,StatusBadRequest is error
		return
	}
	//email is compared now we have to compare password
	//now the user entred password shd be bycrypted and matched with bycrypted password in db

	dbPassword := []byte(dbDetails.Password) //we are storing hashed password in a variable to compare with user password
	userPassword := []byte(details.Password) //we are storing user password in variable whc is with out hashed so we cant compare directly
	// so we convert userPassword in to hash to compare

	//to compare user password to database password whc is  hashed
	passErr := bcrypt.CompareHashAndPassword(dbPassword, userPassword)

	if passErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println(passErr)
		return
	}
	claims := &Claims{
		Email: details.Email,
	}
	//tokem=n contain 1.method(SigningMethodHS256) 2.details(email) 3.key(jwtkey)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) //first 2 methods added
	tokenString, err := token.SignedString(jwtKey)             //third method added

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:  "token",
			Value: tokenString,
			//Expires: expirationTime,
		})

	fmt.Println(dbDetails)

	// var userDetails = dbDetails;
	// delete(dbDetails, "password")

	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return user, nil
	// }

	// func GetUserByEmail(email string) (data map[string]interface{}, err error) {
	// coll := GetCollection(DB, "users")
	// var  user Credentials
	// filter := bson.M{"email": email}
	// fmt.Println(filter)
	// 	err = coll.FindOne(context.TODO(), filter).Decode(&user)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return user, nil
	// }

	// detailss := collection.FindOne(ctx, bson.M{"email": details.Email}).Decode(&dbDetails)

	// json.NewEncoder(w).Encode(bson.M{"sucess": true})
	json.NewEncoder(w).Encode(bson.M{"firstName": dbDetails.FirstName, "lastName": dbDetails.LastName, "Email": dbDetails.Email, "Token": tokenString})
}

//CHANGE PASSWORD POST

func PostChangePassword(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	var dbcredentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	collection := client.Database(db).Collection(col)
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = collection.FindOne(ctx, bson.M{"email": credentials.Email}).Decode(&dbcredentials)
	fmt.Println(dbcredentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	userPass := []byte(credentials.Password)
	dbPass := []byte(dbcredentials.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

	if passErr != nil {
		log.Println(passErr)
		//w.Write([]byte(`{"response":"Wrong Password!"}`))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	json.NewEncoder(w).Encode(bson.M{"sucess": true})
}

//CHANGE PASSWORD PATCH
func PatchChangePassword(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials

	_ = json.NewDecoder(r.Body).Decode(&credentials)
	credentials.Password = getHash([]byte(credentials.Password))
	filter := bson.M{"email": credentials.Email}

	update := bson.D{
		{"$set", bson.D{{"password", credentials.Password}}},
	}

	collection := client.Database(db).Collection(col)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	getresult, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		fmt.Println(err)
		//c["error"] = "an error encountered"
		//json.NewEncoder(response).Encode(c)
		w.WriteHeader(http.StatusBadRequest)

		return
	}
	json.NewEncoder(w).Encode(getresult)

}

// err := db.QueryRow("SELECT Password FROM Users WHERE Username = ?", user.Username).Scan(&storedPass)
//     if err != nil {
//         log.Fatal(err)
//     }
//     // hashed password
//     fmt.Println(storedPass, []byte(storedPass))
//     err = bcrypt.CompareHashAndPassword([]byte(storedPass), []byte(user.Password))
//     if err != nil {
//         // Here is error
//         fmt.Println(err.Error())
//     }

//FORGET PASSWORD

// func forgetPassword(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	var forgetDetails Credentials   //user entered details
// 	var dbForgetDetails Credentials //db  details
// 	json.NewDecoder(r.Body).Decode(&forgetDetails)
// 	collection := client.Database(db).Collection(col) //connection to db
// 	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
// 	collection.FindOne(ctx, bson.M{"email": forgetDetails.Email}).Decode(&dbForgetDetails) //compare email
// 	dbOtp := dbForgetDetails.OTP                                                           //we are storing  db otp in dbotp
// 	userOtp := forgetDetails.OTP                                                           //we are storing userotp
// 	if dbOtp == userOtp {                                                                  //after otps are equal we are storing new password in db
// 		forgetDetails.Password = getHash([]byte(forgetDetails.Password)) //here pasword is hashed
// 		filter := bson.M{"email": forgetDetails.Email}                   //email is stored in var
// 		update := bson.M{"$set": forgetDetails.Password}                 //we are setting
// 		result, err := collection.UpdateOne(ctx, filter, update)         // we r updating in db by above variables
// 		fmt.Println(result)

// 		if err != nil {
// 			fmt.Println("error")
// 			w.Write([]byte("otp matched"))
// 		}
// 	} else {
// 		fmt.Println("OTP is not matched")
// 		w.Write([]byte("otp  not matched"))
// 	}

// }

// func forgetPassword(response http.ResponseWriter, request *http.Request) {
// 	c := make(map[string]interface{})
// 	//json.NewEncoder(response).Encode(c)
// 	var credentials Credentials
// 	var dbcredentials Credentials

// 	_ = json.NewDecoder(request.Body).Decode(&credentials)
// 	fmt.Print(credentials)

// 	//credentials.Password = getHash([]byte(credentials.Password))
// 	// filter := bson.M{"email": credentials.Email}
// 	// update := bson.M{
// 	// 	"$set": credentials,
// 	// }

// 	collection := client.Database(db).Collection(col)
// 	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
// 	err := collection.FindOne(ctx, bson.M{"email": credentials.Email}).Decode(&dbcredentials)
// 	if err != nil {
// 		response.WriteHeader(http.StatusBadRequest)
// 		return
// 	}
// 	dbOtp := dbcredentials.OTP
// 	userOtp := credentials.OTP

// 	//otpErr := userOtp != dbOtp
// 	if userOtp == dbOtp {
// 		credentials.Password = getHash([]byte(credentials.Password))
// 		filter := bson.M{"email": credentials.Email}
// 		update := bson.D{
// 			"$set": credentials,
// 		}
// 		getresult, err := collection.UpdateOne(ctx, filter, update)
// 		if err != nil {
// 			fmt.Println(err)
// 			c["error"] = "an error encountered"
// 			json.NewEncoder(response).Encode(c)
// 			return
// 		}
// 		json.NewEncoder(response).Encode(getresult)
// 		fmt.Print("otp matched")
// 		response.Write([]byte("otp matched"))

// 	} else {
// 		response.Write([]byte("otp not matched"))
// 	}

// }

func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	var dbcredentials Credentials
	json.NewDecoder(r.Body).Decode(&credentials)
	collection := client.Database(db).Collection(col)
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, bson.M{"email": credentials.Email}).Decode(&dbcredentials)
	fmt.Println(dbcredentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	userOtp := (credentials.OTP)
	// dbOtp := "2121"
	dbOtp := (dbcredentials.OTP)
	if userOtp == dbOtp {
		credentials.Password = getHash([]byte(credentials.Password))

		filter := bson.M{"email": credentials.Email}

		update := bson.D{
			{"$set", bson.D{{"password", credentials.Password}}},
		}
		getresult, err := collection.UpdateOne(ctx, filter, update)
		if err != nil {
			fmt.Println(err)

			w.WriteHeader(http.StatusBadRequest)

			return
		}

		json.NewEncoder(w).Encode(getresult)
	} else {
		fmt.Println("wrong otp")
		w.WriteHeader(http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(bson.M{"firstName": dbcredentials.FirstName, "lastName": dbcredentials.LastName, "Email": dbcredentials.Email})

}

//to get user details
func getUser(w http.ResponseWriter, r *http.Request) { // r from user and response from db
	w.Header().Set("content-type", "application/json")
	collection := client.Database(db).Collection(col)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	p, err := collection.Find(ctx, bson.M{}) //p is pointer(couser)  it wont store it is just to point
	if err != nil {
		log.Fatal(err)

	}
	var alldetails []bson.M // in alldetails it stores
	if err = p.All(ctx, &alldetails); err != nil {
		log.Fatal(err)
	}
	fmt.Println(alldetails)
	c := make(map[string]interface{}) //map function  interface
	c["success"] = true
	c["data"] = alldetails //alldetails is stored in c and c is map function so its displays one by one
	json.NewEncoder(w).Encode(c)
}
