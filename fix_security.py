import re

# Read the security.py file
with open("security.py", "r") as file:
    content = file.read()

# Find the create_user function
create_user_match = re.search(r"def create_user$$[^)]*$$.*?return user", content, re.DOTALL)
if create_user_match:
    create_user_code = create_user_match.group(0)
    print("Found create_user function:")
    print(create_user_code)
    
    # Check for problematic fields
    user_creation = re.search(r"user = models\.User$$.*?$$", create_user_code, re.DOTALL)
    if user_creation:
        user_creation_code = user_creation.group(0)
        print("\nUser creation code:")
        print(user_creation_code)
        
        # Check for specific fields
        fields = ["totp_secret", "last_password_change"]
        for field in fields:
            if field in user_creation_code:
                print(f"\nFound problematic field: {field}")
else:
    print("Could not find create_user function in security.py")

# Modify the security.py file to fix the create_user function
modified_content = re.sub(
    r"(user = models\.User$$\s*name=name,\s*email=email,\s*password_hash=hashed_password,\s*mfa_enabled=True).*?($$)",
    r"\1\2",
    content,
    flags=re.DOTALL
)

# Write the modified content to a new file
with open("security_fixed.py", "w") as file:
    file.write(modified_content)
    print("\nCreated security_fixed.py with problematic fields removed")
    