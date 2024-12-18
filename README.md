## **Blockchain Transaction Analysis and Fund Tracing**

This project focuses on analysing blockchain transactions and tracing fund movements across different addresses. By utilising the Tronscan APIs, it retrieves detailed transaction information, verifies recipient addresses and checks the accuracy of received amounts after accounting for transaction fees. Furthermore, the project maps the flow of funds, starting from a specified withdrawal address, by identifying both outgoing and incoming transactions. This comprehensive analysis assists in investigating discrepancies or delays, particularly for transactions involving TRON. By flagging suspicious transactions and ensuring the integrity of blockchain data, this project contributes to a better understanding of cryptocurrency transactions and aids in identifying potential issues such as fraud or unauthorised activity.

## If you find this project useful, please consider giving it a star ⭐ on GitHub. Contributions are also welcome!

---

## **Problem Statement**

With cryptocurrency adoption growing, ensuring the security, transparency and integrity of transactions is critical. However, some transactions may involve scams, unauthorided movements or discrepancies. This project addresses these concerns by:

- Verifying the success and status of transactions
- Validating recipient addresses and amounts
- Detecting unusual or suspicious fund movements.

## **Context**
This investigation involves a 9,172.883118 USDT withdrawal from CoinUnited.io. Although the transaction was marked as "Processing", the recipient has not received the funds and the transaction status remains "Confirming". The investigation revealed:
- Initial attempts to trace the funds from the sender's withdrawal address resulted in an error: "No transactions found."
- No transactions were found for the recipient address either.

## **Key Issue**
A 20 USDT withdrawal was processed via TRON, but the subsequent deposit of 9,172.883118 USDT remains stuck in the transaction history as "Processing". This discrepancy highlights the need to:
- Verify the withdrawal's authenticity and status
- Trace the movement of funds across the blockchain to identify any irregularities.

---

## **Key Steps in the Project**

1. **Fetch Transaction Details**
   - Retrieve detailed transaction information using the Tronscan API, including:
     - Transaction status
     - Recipient address
     - Transaction value

2. **Verify Recipient Address**
   - Compare the recipient address from the transaction details with the expected address.
   - Flag discrepancies for further investigation.

3. **Verify Transaction Amount**
   - Confirm the received amount matches the expected value after accounting for fees a 5 USDT fee.
   - Compare actual and expected values to detect anomalies.

4. **Trace Fund Movements**
   - Analyse all transactions associated with the withdrawal address.
   - Identify outgoing and incoming transactions to map fund flows.
   - Verify correctness of recipient addresses and received amounts.

5. **Error Handling**
   - Handle potential issues, including API request failures, incorrect addresses, network issues or missing transaction data.

6. **User Feedback**
   - Provide users with:
     - Transaction status (successful or failed)
     - Discrepancies in amounts or addresses
     - Results of fund flow tracing

---

## **Project Files**

- **`blockchain_analysis.py`**: The main Python script for transaction analysis, fund tracing and error handling.
- **`crypto_analysis-env`**: Virtual environment setup file with project dependencies.
- **`requirements.txt`**: A list of required Python packages.
- **`.env`**: Configuration file for sensitive information (Tronscan API key).
- **`blockchain_analysis.log`**: Log file containing transaction analysis details.

---

## **Installation and Setup**

1. **Clone the Repository**
   ```bash
   git clone https://github.com/nafisalawalidris/Blockchain-Transaction-Analysis-and-Fund-Tracing.git
   cd Blockchain-Transaction-Analysis-and-Fund-Tracing
   ```

2. **Create a Virtual Environment**
   ```bash
   python -m venv crypto_analysis-env
   ```

3. **Install Required Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up API Keys**
   - Add your API keys for Polygon and Tron networks to a `.env` file for secure access.

5. **Run the Main Script**
   ```bash
   python blockchain_analysis.py
   ```
   - Fetch transaction details
   - Analyse the flow of funds

---

## **Usage Notes**

- Ensure your `.env` file is properly configured with API keys before running the script.
- Use the log file (`blockchain_analysis.log`) to review detailed analysis and errors.
- In case of discrepancies, review the feedback provided by the system and cross-check with blockchain explorers to ensure fund movement accuracy.

---

## **Outcome**
By following this process, the project:
- Provides a systematic approach to analyzing and verifying blockchain transactions.
- Identifies discrepancies, such as missing funds or suspicious activities.
- Assists in investigating and resolving cryptocurrency transaction issues effectively.

---

## **Next Steps**
- If the analysis identifies fraudulent or suspicious activities, the findings can be:
- Escalated to regulatory authorities (financial crime agencies).
- Shared with platform providers to report discrepancies.
- Used to document evidence for legal recourse or further investigation.

---

## **Contributing**
- Contributions to improve this project are welcome! If you find any bugs or have suggestions for new features, please submit an issue or pull request.

---

## **License**
- This project is licensed under the MIT License. See the LICENSE file for details.

---