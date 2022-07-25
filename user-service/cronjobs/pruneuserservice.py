from dotenv import load_dotenv
import subprocess, json, os

def report_prune(channel_id, discord_token, success, error_message):
    #Format the message & stickers
    if success:
        message      = ":white_check_mark: **Prune Results**: Prune successful"
        embed        = "Users and refresh tokens successfully pruned"
        request_body = f'{{ \"content\":\"{message}\", \"embeds\": [{{ \"title\": \"Results\", \"description\": \"{embed}\", \"color\": 2067276 }}] }}'
    else:
        message  = ":x: **Prune Results**: Prune unsuccessful"
        request_body = f'{{ \"content\":\"{message}\", \"embeds\": [{{ \"title\": \"Results\", \"description\": \"Users and refresh tokens failed to prune due to error```{error_message}```\", \"color\": 10038562 }}] }}'
    
    #Format the request body    
    #Send the message
    response = json.loads(subprocess.check_output(['curl', '-X', 'POST', '-H', f"Authorization: Bot {discord_token}", "-H", "Content-Type: application/json", '-d', request_body, f'https://discord.com/api/channels/{channel_id}/messages']))


def prune_users(secret):
    #Call the api and get its response
    response = json.loads(subprocess.check_output(['curl', '-X', 'PUT', '-H', 'Content-Type: application/json', '-d', f'{{ "secret" : "{secret}" }}', f'http://{os.environ.get("HOST", "localhost")}:{os.environ.get("PORT", "8081")}/api/v0/user/prune/']))

    #Check the results
    return response

def main():
    load_dotenv('./cronjobs/.env')
    secret        = os.environ.get('SECRET_KEY', '')
    discord_token = os.environ.get('DISCORD_BOT_TOKEN', '')
    channel_id    = os.environ.get('DISCORD_CHANNEL_ID', '')
    response      = prune_users(secret)
    if response['status'] == 'success':
        report_prune(channel_id, discord_token, True, None)
        report_prune(channel_id, discord_token, False, "This is an error message")
    else:
        report_prune(channel_id, discord_token, False, response['message'])

if __name__ == "__main__":
    main()