# 🛡️ BCF Security Dashboard

This project creates an automated, lightning-fast security dashboard using **Evidence.dev** and **DuckDB**. It processes upto 10GB of logs stored in a private cloud bucket.

## 🚀 How it Works
1. **Data Source:** Raw JSON logs are stored in a private cloud bucket.
2. **Processing:** A **GitHub Action** runs once a day/hour.
3. **Engine:** **DuckDB** crunches the logs inside the GitHub runner to create a tiny summary.
4. **Frontend:** **Evidence.dev** renders the summary into a static site.
5. **Deployment:** The site is hosted on a static site.

## 🛠️ Local Development
If you want to tweak the charts locally:

1. Install dependencies: `npm install`
2. Create a `.env` file with your own cloud bucket keys (do NOT commit this!).
3. Run the dev server: `npm run dev`

## 🔐 Security Note
- Raw logs are **never** committed to this repo.
