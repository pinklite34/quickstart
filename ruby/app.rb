require 'base64'
require 'date'
require 'json'
require 'plaid'
require 'sinatra'

set :public_folder, File.dirname(__FILE__) + '/static'
# set :port, ENV['PLAID_ENV'] || 4567

client = Plaid::Client.new(env: ENV['PLAID_ENV'],
                           client_id: ENV['PLAID_CLIENT_ID'],
                           secret: ENV['PLAID_SECRET'],
                           public_key: ENV['PLAID_PUBLIC_KEY'])

access_token = nil

get '/' do
  erb :index
end

# Exchange token flow - exchange a Link public_token for
# an API access_token
# https://plaid.com/docs/#exchange-token-flow
post '/get_access_token' do
  exchange_token_response =
    client.item.public_token.exchange(params['public_token'])
  access_token = exchange_token_response['access_token']
  pretty_print_response(exchange_token_response)

  content_type :json
  exchange_token_response.to_json
end

# Retrieve Transactions for an Item
# https://plaid.com/docs/#transactions
get '/transactions' do
  now = Date.today
  thirty_days_ago = (now - 30)
  begin
    product_response =
      client.transactions.get(access_token, thirty_days_ago, now)
    pretty_print_response(product_response)
    content_type :json
    { transactions: product_response }.to_json
  rescue Plaid::PlaidAPIError => e
    error_response = format_error(e)
    pretty_print_response(error_response)
    content_type :json
    error_response.to_json
  end
end

# Retrieve ACH or ETF account numbers for an Item
# https://plaid.com/docs/#auth
get '/auth' do
  begin
    product_response = client.auth.get(access_token)
    pretty_print_response(product_response)
    content_type :json
    { auth: product_response }.to_json
  rescue Plaid::PlaidAPIError => e
    error_response = format_error(e)
    pretty_print_response(error_response)
    content_type :json
    error_response.to_json
  end
end

# Retrieve Identity data for an Item
# https://plaid.com/docs/#identity
get '/identity' do
  begin
    product_response = client.identity.get(access_token)
    pretty_print_response(product_response)
    content_type :json
    { identity: product_response }.to_json
  rescue Plaid::PlaidAPIError => e
    error_response = format_error(e)
    pretty_print_response(error_response)
    content_type :json
    error_response.to_json
  end
end

# Retrieve real-time balance data for each of an Item's accounts
# https://plaid.com/docs/#balance
get '/balance' do
  begin
    product_response = client.accounts.balance.get(access_token)
    pretty_print_response(product_response)
    content_type :json
    { balance: product_response }.to_json
  rescue Plaid::PlaidAPIError => e
    error_response = format_error(e)
    pretty_print_response(error_response)
    content_type :json
    error_response.to_json
  end
end

# Retrieve an Item's accounts
# https://plaid.com/docs/#accounts
get '/accounts' do
  begin
    product_response = client.accounts.get(access_token)
    pretty_print_response(product_response)
    content_type :json
    { accounts: product_response }.to_json
  rescue Plaid::PlaidAPIError => e
    error_response = format_error(e)
    pretty_print_response(error_response)
    content_type :json
    error_response.to_json
  end
end

# Create and then retrieve an Asset Report for one or more Items. Note that an
# Asset Report can contain up to 100 items, but for simplicity we're only
# including one Item here.
# https://plaid.com/docs/#assets
# rubocop:disable Metrics/BlockLength
get '/assets' do
  begin
    asset_report_create_response =
      client.asset_report.create([access_token], 10, {})
    pretty_print_response(asset_report_create_response)
  rescue Plaid::PlaidAPIError => e
    error_response = format_error(e)
    pretty_print_response(error_response)
    content_type :json
    error_response.to_json
  end

  asset_report_token = asset_report_create_response['asset_report_token']

  asset_report_json = nil
  num_retries_remaining = 20
  while num_retries_remaining > 0
    begin
      asset_report_get_response = client.asset_report.get(asset_report_token)
      asset_report_json = asset_report_get_response['report']
      break
    rescue Plaid::PlaidAPIError => e
      if e.error_code == 'PRODUCT_NOT_READY'
        num_retries_remaining -= 1
        sleep(1)
        next
      end
      error_response = format_error(e)
      pretty_print_response(error_response)
      content_type :json
      return error_response.to_json
    end
  end

  if asset_report_json.nil?
    content_type :json
    return {
      error: {
        error_code: 0,
        error_message: 'Timed out when polling for Asset Report'
      }
    }.to_json
  end

  asset_report_pdf = client.asset_report.get_pdf(asset_report_token)

  content_type :json
  {
    json: asset_report_json,
    pdf: Base64.encode64(asset_report_pdf)
  }.to_json
end
# rubocop:enable Metrics/BlockLength

# Retrieve high-level information about an Item
# https://plaid.com/docs/#retrieve-item
get '/item' do
  item_response = client.item.get(access_token)
  institution_response =
    client.institutions.get_by_id(item_response['item']['institution_id'])
  content_type :json
  { item: item_response['item'],
    institution: institution_response['institution'] }.to_json
end

post '/set_access_token' do
  access_token = params['access_token']
  item = client.item.get(access_token)
  content_type :json
  { error: false, item_id: item['item']['item_id'] }.to_json
end

def format_error(err)
  { error: { error_code: err.error_code, error_message: err.error_message } }
end

def pretty_print_response(response)
  puts JSON.pretty_generate(response)
end
# Colour constants
bold=`tput bold`
green=`tput setaf 2`
red=`tput setaf 1`
reset=`tput sgr0`

ALICE_PORT=10001
BOB_PORT=10002

ALICE_LOG=bin/testnet/test/alice.txt
BOB_LOG=bin/testnet/test/bob.txt

if test -d bin; then cd bin; fi

echo "${bold}Mounting a RAM disk for server output in test directory!${reset}"
if mountpoint -q -- "test"; then
    sudo umount test
fi

rm -r test | true # in case this is the first time being run
mkdir test && sudo mount -t tmpfs -o size=5000m tmpfs test

# Source Intel Libraries
source /opt/intel/sgxsdk/environment

pushd ../../ # go to source directory
echo "${bold}Starting two ghost teechain enclaves...${reset}"

echo "${bold}Spawning enclave ALICE listening on port $ALICE_PORT in $ALICE_LOG ${reset}"
./teechain ghost -d -p $ALICE_PORT > $ALICE_LOG 2>&1 &
sleep 1

echo "${bold}Spawning enclave BOB listening on port $BOB_PORT in $BOB_LOG ${reset}"
./teechain ghost -d -p $BOB_PORT > $BOB_LOG 2>&1 &
sleep 1

echo -n "${red}Waiting until enclaves are initialized ...!${reset}"
for u in alice bob; do  #TODO: generalize to multiple parties (not just 4)
    while [ "$(grep -a 'Enclave created' bin/testnet/test/${u}.txt | wc -l)" -eq 0 ]; do
        sleep 0.1
        echo -n "."
    done
done

# Create primaries
./teechain primary -p $ALICE_PORT
./teechain primary -p $BOB_PORT

# Setup up primaries with number of deposits
./teechain setup_deposits 5 -p $ALICE_PORT
./teechain setup_deposits 3 -p $BOB_PORT

# Deposits made
./teechain deposits_made mmY6ijr6uLP3DdRFC4nwL23HSKsH2xgy74 1 5 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 0 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 1 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 2 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 3 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 4 1 -p $ALICE_PORT
./teechain deposits_made my6NJU1T6gL5f3TfmSPN4idUytdCQHTmsU 1 3 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 0 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 1 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 2 1  -p $BOB_PORT

# Create and establish a channel between Alice and Bob
./teechain create_channel -p $BOB_PORT &
sleep 1
./teechain create_channel -i -r 127.0.0.1:$BOB_PORT -p $ALICE_PORT # Initiator

sleep 2

# Extract the channel id for the channel created
CHANNEL_1=$(grep "Channel ID:" $ALICE_LOG | awk '{print $3}')

# Verified the setup transactions are in the blockchain
./teechain verify_deposits $CHANNEL_1 -p $BOB_PORT &
./teechain verify_deposits $CHANNEL_1 -p $ALICE_PORT

sleep 2

# Alice and Bob add deposits to their channels now
./teechain add_deposit $CHANNEL_1 0 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 0 -p $BOB_PORT

# Alice check balance matches expected
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 1, remote balance is: 1"; then
    echo "Alice's balance check failed on channel setup!"; exit 1;
fi

# Send from Bob to Alice
./teechain send $CHANNEL_1 1 -p $BOB_PORT

# Alice check balance after
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 2, remote balance is: 0"; then
    echo "Alice's balance check failed after send!"; exit 1;
fi

# Send from Bob to Alice should fail. Bob check balance, shouldn't have changed
./teechain send $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 0, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
# Add deposit from bob's side and check balance
./teechain add_deposit $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 1, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob added another deposit to his channel!"
# Send from Bob to Alice and check balance is back to zero
./teechain send $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 0, remote balance is: 3"; then
    echo "Bob's balance check failed!"; exit 1;
fi
# Send from Alice to Bob and check Bob's balance on Alice's side
./teechain send $CHANNEL_1 1 -p $ALICE_PORT
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 2, remote balance is: 1"; then
    echo "Alice's balance check failed!"; exit 1;
fi
# Bob remove deposit and check balance
./teechain remove_deposit $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 0, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob removed the deposit from his channel!"
# Bob try to remove first deposit, should fail as insufficient funds
./teechain remove_deposit $CHANNEL_1 0 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 0, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob removed his last deposit from the channel!"
# Bob now send 1 to alice
./teechain send $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 0, remote balance is: 1"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob sent 1 to Alice!"
# Alice removed last deposit from channel
./teechain remove_deposit $CHANNEL_1 0 -p $ALICE_PORT
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 0, remote balance is: 0"; then
    echo "Alice's balance check failed!"; exit 1;
fi
echo "Alice removed her last deposit from the channel!"
# Bob now send 1 to alice
./teechain send $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 0, remote balance is: 0"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob tried to send 1 to alice, but it didnt work!"
# Add all the deposits to the channel (both sides)
./teechain add_deposit $CHANNEL_1 0 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 1 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 2 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 3 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 4 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 0 -p $BOB_PORT
./teechain add_deposit $CHANNEL_1 1 -p $BOB_PORT
./teechain add_deposit $CHANNEL_1 2 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $ALICE_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 5, remote balance is: 3"; then
    echo "Alice's balance check failed!"; exit 1;
fi
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 3, remote balance is: 5"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "All deposits added to the channel!"
# Bob now send 3 to alice
./teechain send $CHANNEL_1 3 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 0, remote balance is: 8"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob sent all 3 to Alice!"
# Settle and shutdown
./teechain settle_channel $CHANNEL_1 -p $ALICE_PORT
# Alice decides to get her unused deposits out (there are no used deposits!)
./teechain shutdown -p $ALICE_PORT
popd # return to bin directory
../kill.sh
echo "${bold}Looks like the test passed!${reset}"
  -----BEGIN CERTIFICATE-----
MIIDhTCCAm2gAwIBAgIJALjCgEBIwDscMA0GCSqGSIb3DQEBBQUAMFkxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xMzAzMDgxMzQw
MDJaFw0yMzAzMDYxMzQwMDJaMFkxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21l
LVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNV
BAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOTL
p47Qy1hovBC6VWi33CCpq5r5+QHnt5PLsjhOoZ0VjHI0KYNMPkT9yfwJZO8vHEsW
dDoW+fRojp+VO6JOYcO1JAr0jBlnzfOlr+zBHKvaEWylku9DS5ZbxLnj4AQe5m5/
uqtlQt4ib4vXQr3yfW8B9Jy55OfWV8m9orfxubOzK1Ll0LeDwubKgUwuzB3auJKb
VNsIlZQzrKDzMoTExtKF/7cSUC+5+1UHFy9rUh9VOtU2RkFJQgOPOyw9lmg7pCfl
uurz4Q8wjSchhWvMnEc8YenqOaA+AcmlFiHwQq3z0aILCa5IEUOUzwER4bZM6eDe
8rZLG+uRAABhhfC/LfUCAwEAAaNQME4wHQYDVR0OBBYEFEhAKuSwT9BxLaHcxzmn
CDZ7bxycMB8GA1UdIwQYMBaAFEhAKuSwT9BxLaHcxzmnCDZ7bxycMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAIK1pI70uzMET8QAJ6o0rBsuYnat9WeL
Y/27yKWg440BoWYxI6XJPP+nnncesGxcElnQCPkut8ODIGG037WKuQNRMr7dBQeU
MIaIxKGZETGIj5biao6tqYuWwIS54NxOTIUVx4QomXnyLNyE0Mj4ftD8bKEIuVfV
2bDC6UjN02lPh2IsV+th5oOr3BShwafu+7CAKLSaidraUW/hGKSWpMgBSBHnA2tD
W3mLidFxB2ufi6ufT87HliC6AJw6S9A5+iuAIEuRGV4zhc4BZpKTeeFRVWYPUBtp
/SoNIeLQ4ORhIFQjTY2nEq2lGnCJ0JcTTt1gVNbsEitRtw0eAUtMTXs=
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuZ4RZVnjh8kS32TZn7pMWJevf473pLqecObWMLmeB6FIzpvf
kYi8RyLD9Q87QjmIhbrqFncyaBaw1iz5sx2sVM2+acwlocN4UHPBCxwvmtUeEn1t
WMp29D4NetJNssvq7PxzcXY7bv7FQ7q7kJ5KpoBc+OBu/4vdQhM0gkR5QEL52KNj
C8umfhc2aEeRn4et9lBqNlE4WjH3s5tOO3DqNt5kQ28hulcSaiPMaKPcjqmAYz8+
VLOY7fefGNBecr72MaA5St+oc0TDK6msHPoTtYe4b6r6AsyM9O+7f82idtWK9nu/
rjQZP2UeMQvqUtQj+Ar3WoM60SkEQ8Ckq6PQPwIDAQABAoIBAFUlZFd4r34HR8gA
LDAwNnthQZkjDQicrredvF1nmE1pt8tHB3xsG+oJ0Zgln4pWeADYaC9cCFxlJENr
KDP5Bad1JcbEZfLZhuRo5QHisRe2cXAL51AWuBB8MpTHyeqdzitd9tryYHsfFYBn
NUk2w4mzUnK8CU7iauG3i5vCK1jFV9OvedeQGjmKcJ39U4R8qOQesTP1x0tc7C8Y
SgSNaicZKXcHOlHntk6sGfpCekDX0bPKAOB2CMtbujeUNB/wgM/eEGLugdddXHfV
GErnqqnSCUog3bhZLaEOdl4XOJZtBmKIzQcUecNH3myADgpSm+AethCYErRqmvIj
FhXNfVkCgYEA7B2NjuOeaxoIgqPVN+DFVOVOv25AODLpgZDrfPZqr0E231LaexRn
xtsuJpxQ/lGPgY6dOrhX6d5HEQ2JrFDiKyv+uP7V/s9Wp562UhSMRLzuXWg7phto
yuia2bwj9k4Fwl9b3tQfJMxUulv2Bkq4+ZtuX0bFw8P4C3xwQMLQCgMCgYEAyT/S
UFIFp2u/7tXce5qrT3Z/SMe3qa+1DeosmhdCNQdJhV0p7rARX0bl+UN1oeDg65Sb
khzmTf+zpB0Nho63+W/CjlSdHBBFPTgSgjejkfiENfW63HBT18K0ya2LC4+fOuWg
e35VBJjKZT4nUTjZ/rscdeKNve4SvSWl3dFPqhUCgYEAgqIbJroydKkTmkvQdLjs
FHtF5U23RCCO5ntqflnLTqkzFb2+WShB/lhXoU8M1JgFYLWpsco6AY9UHFA0Il0h
tKcDqBB+Dxthox2BW8o4jPNGofFARzeU8+ZbfinEb8pdD1w49QDBNlfCbNTiOjrv
OlJPb3E1i4kJ3Dj91iayeUcCgYEAgS5qfgxofLN5nIHC6cS6umNCCSHKDy4udiQf
RTow0YE//E91HzX9sL792CcpVyPWvOHDiuLqIp9EXNAZYooyJfdLV7mQr/bxuv5H
Qzcb1BNGKqz1qZKg/xqImfzACEfE2jWT8jGBuVWqdZqT+lsX85+AAVvPyF8NwERu
WBiHnpECgYA28LMcfOVplez7z7wxzoVZyq7I7yV50RCxZiJ6GepZPzTnqR2LAmb6
2qMOJkShHk/pydtF+49j9/MjWJexGWaCbsFaei/bnsZfskEF+/2MFmBp6fAN1FRP
FLNEF+YTPz6yFCNWecZ2INEAokEi2D809XhDQwiJz0E2vEzhR93fDg==
-----END RSA PRIVATE KEY-----
  
© 2019 GitHub, Inc.
