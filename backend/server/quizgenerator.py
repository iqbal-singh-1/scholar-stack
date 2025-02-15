import requests
import random

class DynamicTest:
    def __init__(self):
        self.api_url = "https://the-trivia-api.com/v2/questions"

        self.categories = {
            "1": "General Knowledge",
            "2": "Science",
            "3": "History",
            "4": "Sports",
            "5": "Music"
        }
        
        self.difficulty_levels = ["easy", "medium", "hard"]

    def fetch_questions(self, topic, difficulty, num_questions):
        params = {
            "categories": topic.lower().replace(" ", "-"),
            "limit": num_questions,
            "difficulty": difficulty
        }

        try:
            response = requests.get(self.api_url, params=params)
            if response.status_code == 200:
                data = response.json()
                return self.normalize_questions(data)
        except Exception as e:
            print(f"Error fetching questions: {e}")
        return []

    def normalize_questions(self, data):
        normalized = []
        for item in data:
            normalized.append({
                "question": item.get("question"),
                "options": item.get("incorrectAnswers", []) + [item.get("correctAnswer")],
                "correct": item.get("correctAnswer")
            })
        return normalized
