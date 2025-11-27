
import os
import sys
from datetime import timedelta

# Mock environment variables
os.environ["SECRET_KEY"] = "test_secret"

# Add current directory to path so we can import auth
sys.path.append(os.getcwd())

try:
    import auth
    print("Successfully imported auth")
except Exception as e:
    print(f"Failed to import auth: {e}")
    sys.exit(1)

def test_create_access_token():
    data = {"sub": "testuser"}
    
    # Test with default expiration
    try:
        token = auth.create_access_token(data)
        print("Successfully created token with default expiration")
    except Exception as e:
        print(f"Failed to create token with default expiration: {e}")
        sys.exit(1)

    # Test with custom expiration
    try:
        expires = timedelta(minutes=30)
        token = auth.create_access_token(data, expires_delta=expires)
        print("Successfully created token with custom expiration")
    except Exception as e:
        print(f"Failed to create token with custom expiration: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_create_access_token()
