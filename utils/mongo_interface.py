from typing import Any, Dict, List, Optional, Union
import pymongo
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.cursor import Cursor
import gridfs


class MongoInterface:
    """
    A class to interact with a MongoDB collection and GridFS.

    Attributes:
        client (pymongo.MongoClient): The MongoDB client.
        db (pymongo.database.Database): The MongoDB database.
        collection (pymongo.collection.Collection): The MongoDB collection.
        fs (gridfs.GridFS): The GridFS interface for storing large files.
    """

    def __init__(self, host: str, port: int):
        """
        Initialize the MongoInterface.

        Args:
            host (str): The MongoDB host.
            port (int): The MongoDB port.
        """
        self.client: pymongo.MongoClient = pymongo.MongoClient(host, port)
        self.db: Database = self.client["vulnsrc"]
        self.collection: Collection = self.db["cves"]
        self.fs: gridfs.GridFS = gridfs.GridFS(self.db)

    def insert(self, data: Dict[str, Any]) -> None:
        """
        Insert a single document into the collection.

        Args:
            data (Dict[str, Any]): The document to insert.
        """
        self.collection.insert_one(data)

    def insert_many(self, data: List[Dict[str, Any]]) -> None:
        """
        Insert multiple documents into the collection.

        Args:
            data (List[Dict[str, Any]]): The documents to insert.
        """
        self.collection.insert_many(data)

    def find(self, query: Dict[str, Any]) -> Cursor:
        """
        Find documents matching a query.

        Args:
            query (Dict[str, Any]): The query to match documents.

        Returns:
            Cursor: A cursor to iterate over matching documents.
        """
        return self.collection.find(query)

    def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Find a single document matching a query.

        Args:
            query (Dict[str, Any]): The query to match a document.

        Returns:
            Optional[Dict[str, Any]]: The matched document or None if no match.
        """
        return self.collection.find_one(query)

    def update(self, query: Dict[str, Any], data: Dict[str, Any]) -> None:
        """
        Update a single document matching a query.

        Args:
            query (Dict[str, Any]): The query to match a document.
            data (Dict[str, Any]): The data to update in the document.
        """
        self.collection.update_one(query, {"$set": data})

    def delete(self, query: Dict[str, Any]) -> None:
        """
        Delete a single document matching a query.

        Args:
            query (Dict[str, Any]): The query to match a document.
        """
        self.collection.delete_one(query)

    def delete_many(self, query: Dict[str, Any]) -> None:
        """
        Delete multiple documents matching a query.

        Args:
            query (Dict[str, Any]): The query to match documents.
        """
        self.collection.delete_many(query)

    def drop(self) -> None:
        """
        Drop the collection.
        """
        self.collection.drop()

    def count(self) -> int:
        """
        Count the number of documents in the collection.

        Returns:
            int: The number of documents.
        """
        return self.collection.count_documents({})

    def close(self) -> None:
        """
        Close the MongoDB connection.
        """
        self.client.close()

    def insert_file(self, file_path: str, file_name: str) -> str:
        """
        Insert a file into GridFS.

        Args:
            file_path (str): The path to the file to insert.
            file_name (str): The name to assign to the file in GridFS.

        Returns:
            str: The ID of the stored file.
        """
        with open(file_path, "rb") as f:
            file_id = self.fs.put(f, filename=file_name)
        return str(file_id)
