package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func SetupDatabaseConnection() *gorm.DB{
	errENV := godotenv.Load()
	if errENV != nil{
		panic("failed to load env")
	}
	
	dbUser :=os.Getenv("DB_USER")
	dbPass :=os.Getenv("DB_PASS")
	dbHost :=os.Getenv("DB_HOST")
	dbName :=os.Getenv("DB_NAME")
	
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?charset=utf8&parseTime=True&loc=Local",dbUser,dbPass,dbHost,dbName)
 	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err !=nil{
		panic("failed to create connection to database")
	}
	return db
}
func CloseDatabaseConnection(db *gorm.DB){
	dbSQL,err  :=db.DB()
	if err !=nil{
		panic("failed to close connection from database")
	}

	dbSQL.Close()
}
