import sqlite3
from grass_bot import init_db, add_or_update_account, get_encryption_key

# Initialize database
init_db()

# Get or create encryption key
key = get_encryption_key()

# Add your account details
add_or_update_account(
    email="jahsonben2021@gmail.com",
    user_id="2nvBhEgClVZL05LDoUIdJbM54FG",
    bearer_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkJseGtPeW9QaWIwMlNzUlpGeHBaN2JlSzJOSEJBMSJ9.eyJ1c2VySWQiOiIybnZCaEVnQ2xWWkwwNUxEb1VJZEpiTTU0RkciLCJlbWFpbCI6ImphaHNvbmJlbjIwMjFAZ21haWwuY29tIiwic2NvcGUiOiJVU0VSIiwiaWF0IjoxNzQ2NjE2MDc5LCJuYmYiOjE3NDY2MTYwNzksImV4cCI6MTc3NzcyMDA3OSwiYXVkIjoid3luZC11c2VycyIsImlzcyI6Imh0dHBzOi8vd3luZC5zMy5hbWF6b25hd3MuY29tL3B1YmxpYyJ9.J-o6TG92Wi_vIWeNdBt8pII6ozAVvwF2TaQiVB8zYZE6gqeM1bzGtJRRChUSGpQlkGmGAzKxDmYrp-ixHTJKcdAmFBc2Ccczxeru0SZKONatHsU7xsGeBNDLvCy6wWCL71wS1s4_P6kX38NPs6vMS07E6GPLLRjdIycnFoq8-yULPmarUuGhwLS_F79oZbCqP2uwqQnKfCgWxN5ksejFscwqqgJY0GAY99esvZLrGyFJ4Ypr75QGreI1wjp8G003_sUnfgS3MGlbf14ACwJvePgDaR0QZzS90jkfs5hLoKoiWlG1jQb1IWRiVu-nUVRVf4EO6i16Q_drRnitNH7Sdg",
    key=key
)

# Verify database
conn = sqlite3.connect('grass_accounts.db')
cursor = conn.cursor()
cursor.execute('SELECT email, user_id, bearer_token, status FROM accounts')
print(cursor.fetchall())
conn.close()
