module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class AdyenGateway < Gateway
      self.test_url = 'https://pal-test.adyen.com/pal/servlet/Payment/v12'
      self.live_url = 'https://pal-live.adyen.com/pal/servlet/Payment/v12'

      self.supported_countries = ['US']                                           # @todo Figure this out at all
      self.default_currency = 'USD'                                               # @todo Confirm this
      self.supported_cardtypes = [:visa, :master, :american_express, :discover,
                                  :diners_club, :jcb]                             # @todo Confirm this

      self.homepage_url = 'http://www.adyen.com/'
      self.display_name = 'Adyen'

      # Adyen expects non-decimal values
      self.money_format = :cents

      # Not sure if this is even worth it. Most of the codes don't map back to the very limited standard set.
      STANDARD_ERROR_CODE_MAPPING = {
        # '3d-secure: Authentication failed' => STANDARD_ERROR_CODE[],
        # 'Acquirer Fraud' => STANDARD_ERROR_CODE[],
        # 'Blocked Card' => STANDARD_ERROR_CODE[],
        # 'Cancelled' => STANDARD_ERROR_CODE[],
        'CVC Declined' => STANDARD_ERROR_CODE[:incorrect_cvc],
        # 'Refused' => STANDARD_ERROR_CODE[],
        'Declined Non Generic' => STANDARD_ERROR_CODE[:card_declined],
        # 'Acquirer Error' => STANDARD_ERROR_CODE[],
        'Expired Card' => STANDARD_ERROR_CODE[:expired_card],
        # 'FRAUD' => STANDARD_ERROR_CODE[],
        # 'FRAUD-CANCELLED' => STANDARD_ERROR_CODE[],
        # 'Invalid Amount' => STANDARD_ERROR_CODE[],
        'Invalid Card Number' => STANDARD_ERROR_CODE[:invalid_number],
        'Invalid Pin' => STANDARD_ERROR_CODE[:incorrect_pin],
        # 'Issuer Unavailable' => STANDARD_ERROR_CODE[],
        # 'Not enough balance' => STANDARD_ERROR_CODE[],
        # 'Not Submitted' => STANDARD_ERROR_CODE[],
        # 'Not supported' => STANDARD_ERROR_CODE[],
        # 'Pending' => STANDARD_ERROR_CODE[],
        # 'Pin tries exceeded' => STANDARD_ERROR_CODE[],
        # 'Pin validation not possible' => STANDARD_ERROR_CODE[],
        # 'Referral' => STANDARD_ERROR_CODE[],
        # 'Restricted Card' => STANDARD_ERROR_CODE[],
        # 'Revocation Of Auth' => STANDARD_ERROR_CODE[],
        # 'Shopper Cancelled' => STANDARD_ERROR_CODE[],
        # 'Withdrawal count exceeded' => STANDARD_ERROR_CODE[],
        # 'Withdrawal amount exceeded' => STANDARD_ERROR_CODE[],
        # 'Transaction Not Permitted' => STANDARD_ERROR_CODE[],
        # 'Unknown' => STANDARD_ERROR_CODE[]
      }

      def initialize(options={})
        # * <tt>:order_id</tt> - The order number
        # * <tt>:ip</tt> - The IP address of the customer making the purchase
        # * <tt>:customer</tt> - The name, customer number, or other information that identifies the customer
        # * <tt>:invoice</tt> - The invoice number
        # * <tt>:merchant</tt> - The name or description of the merchant offering the product
        # * <tt>:description</tt> - A description of the transaction
        # * <tt>:email</tt> - The email address of the customer
        # * <tt>:currency</tt> - The currency of the transaction.  Only important when you are using a currency that is not the default with a gateway that supports multiple currencies.
        # * <tt>:billing_address</tt> - A hash containing the billing address of the customer.
        # * <tt>:shipping_address</tt> - A hash containing the shipping address of the customer.

        requires!(options, :merchant, :username, :password) # @todo Confirm this
        super
      end

      def purchase(money, payment_method, options={})
        response = authorize(money, payment_method, options)
        return response unless response.success?
        capture(money, response.authorization)
      end

      def authorize(money, payment_method, options={})
        request = {}
        add_amount(request, money, options)
        add_invoice(request, options)
        add_customer_data(request, options)
        add_payment_method(request, payment_method)

        commit(:authorise, request)
      end

      def capture(money, authorization, options={})
        request = {}
        add_modificaiton_amount(request, money, options)
        add_original_reference(request, authorization)

        commit(:capture, request)
      end

      def refund(money, authorization, options={})
        request = {}
        add_modificaiton_amount(request, money, options)
        add_original_reference(request, authorization)

        commit(:refund, request)
      end

      def void(authorization, options={})
        request = {}
        add_original_reference(request, authorization)

        commit(:cancel, request)
      end

      def verify(credit_card, options={})
        # MultiResponse.run(:use_first_response) do |r|
        #   r.process { authorize(100, credit_card, options) }
        #   r.process(:ignore_result) { void(r.authorization, options) }
        # end
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript
          .gsub(%r((Authorization: Basic )\w+), '\1[FILTERED]')
          .gsub(%r((&?number[^a-zA-Z\d]+)\d+(&?)), '\1[FILTERED]\2')
          .gsub(%r((&?cvc[^a-zA-Z\d]+)\d+(&?)), '\1[FILTERED]\2')
      end

      private

      def add_customer_data(request, options)
        request[:shopperIP] = options[:ip]
        request[:shopperEmail] = options[:email]
        request[:shopperReference] = options[:email] # @todo should this be the customer ID? Can we get that?
      end

      def add_merchant_data(request, options={})
        request[:merchantAccount] = options.empty? ? @options[:merchant] : options[:merchant]
      end

      def add_invoice(request, options)
        request[:reference] = options[:invoice] # @todo This probably shouldn't be the invoice since an invoice could have multiple payments
        # request[:merchantOrderReference] = options[:order] # @todo would be good to add this if possible
      end

      def add_amount(request, money, options)
        request[:amount] = {
          value: amount(money),
          currency: (options[:currency] || currency(money))
        }
      end

      def add_modificaiton_amount(request, money, options)
        request[:modificationAmount] = {
          value: amount(money),
          currency: (options[:currency] || currency(money))
        }
      end

      def add_original_reference(request, ref)
        request[:originalReference] = ref
      end

      def add_payment_method(request, payment_method)
        # @todo Enable the ten million other payment methods
        raise ArgumentError, 'Unsupported funding source provided' unless supported_cardtypes.include? card_brand(payment_method).to_sym
        add_credit_card(request, payment_method)
      end

      def add_credit_card(request, payment_method)
        request[:card] = {
          expiryMonth: format(payment_method.month, :two_digits),
          expiryYear: format(payment_method.year, :four_digits),
          holderName: payment_method.name,
          number: payment_method.number,
          cvc: payment_method.verification_value
        }
      end

      def parse(body)
        JSON.parse(body, symbolize_names: true)
      end

      def commit(action, parameters)
        add_merchant_data(parameters)

        response = begin
          parse(ssl_post(url(action), request_data(action, parameters), headers))
        rescue ActiveMerchant::ResponseError => e
          # Adyen returns HTTP status codes that trigger exceptions in a range of circumstances that we should recover
          # from. To get some sane messages back we need to extract the original response from the exception.
          raise e unless %w(400 403 404 422 500).include?(e.response.code)
          parse(e.response.body)
        end

        success = success_from(action, response)

        Response.new(
          success,
          message_from(action, response, success),
          response,
          authorization: authorization_from(action, response),
          # avs_result: AVSResult.new(code: response["some_avs_response_key"]),
          # cvv_result: CVVResult.new(response["some_cvv_response_key"]),
          error_code: error_code_from(action, response, success),
          test: test?
        )
      end

      def url(action)
        (test? ? test_url : live_url) + '/' + action.to_s
      end

      def success_from(action, response)
        return response[:resultCode] == 'Authorised' if action == :authorise
        response[:response] == "[#{action.to_s}-received]"
      end

      def message_from(action, response, success=nil)
        success = success.nil? ? success_from(action, response) : success
        if success
          'Succeeded'
        else
          response[:refusalReason] || "Error #{response[:errorCode]} - #{response[:message]}"
        end
      end

      def authorization_from(action, response)
        response[:pspReference]
      end

      def request_data(action, parameters = {})
        recursively_compact_hash(parameters).to_json
      end

      def error_code_from(action, response, success=nil)
        success = success.nil? ? success_from(action, response) : success
        unless success
          action == :authorise ? map_error_codes(response[:refusalReason]) : response[:result]
        end
      end

      def map_error_codes(error)
        STANDARD_ERROR_CODE_MAPPING[error] || error
      end

      def headers
        {
          'Content-Type'  => 'application/json',
          'Authorization' => authorization_header
        }
      end

      def authorization_header
        'Basic ' + Base64.strict_encode64(@options[:username].to_s + ':' + @options[:password].to_s)
      end

      def recursively_compact_hash(hash)
        proc = Proc.new do |k, v|
          (v.kind_of?(Hash)) ? (v.delete_if(&proc); v.empty? ) : v.nil?
        end
        hash.delete_if &proc
      end
    end
  end
end
