import React, { useEffect, useState } from "react";
import axios from "axios";
import { Box, Container, Typography, Paper, Grid, Button } from "@mui/material";
import { Doughnut, Pie, Line, Bar } from "react-chartjs-2";
import LoadingComponent from "./Loading";
import { Link, useNavigate } from "react-router-dom";
import 'bootstrap/dist/css/bootstrap.min.css'
import BASE_URL from "./baseURL";

function Dashboard() {
  const [totalApis, setTotalApis] = useState(0);
  const [totalVulnerabilities, setTotalVulnerabilities] = useState(0);
  const [codeScore, setCodeScore] = useState(0);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const [pieData, setPieData] = useState({
    labels: [],
    datasets: [
      {
        label: "Vulnerability Types",
        data: [],
        backgroundColor: [],
        hoverOffset: 4,
        borderWidth: 0,
      },
    ],
  });
  const [lineData, setLineData] = useState({
    labels: [],
    datasets: [
      {
        label: "Vulnerabilities Over Time",
        data: [],
        fill: false,
        borderColor: "",
        tension: 0.1,
      },
    ],
  });
  const [barData, setBarData] = useState({
    labels: [],
    datasets: [
      {
        label: "Severity of Vulnerabilities",
        data: [],
        backgroundColor: [],
      },
    ],
  });
  const [codeScoreData, setCodeScoreData] = useState({
    labels: ["Secure", "Vulnerable"],
    datasets: [
      {
        label: "Code Quality Score",
        data: [],
        backgroundColor: ["#CE93D8", "#AB47BC"],
        hoverOffset: 4,
      },
    ],
  });

  const colorPalette = [
    "#F3E5F5", // Lavender (lightest)
    "#E1BEE7", // Light lavender
    "#CE93D8", // Pastel purple
    "#BA68C8", // Soft purple
    "#AB47BC", // Moderate purple
    "#9C27B0", // Vivid purple
    "#8E24AA", // Deep purple
    "#7B1FA2", // Darker purple
    "#6A1B9A", // Persian indigo
    "#4A148C", // Deep indigo (darkest)
    "#38016B"
  ];

  const colorPalette2 = [
    "#BA68C8", // Soft purple
    "#9C27B0", // Vivid purple
    "#7B1FA2", // Darker purple
    "#4A148C", // Deep indigo (darkest)
  ];

  const fetchData = () => {
    axios
      .get(`${BASE_URL}/api/total_apis`)
      .then((response) => setTotalApis(response.data))
      .catch((error) => console.error("Error fetching total APIs:", error));

    // Fetch total vulnerabilities
    axios
      .get(`${BASE_URL}/api/total_vulnerabilities`)
      .then((response) => setTotalVulnerabilities(response.data))
      .catch((error) =>
        console.error("Error fetching total vulnerabilities:", error)
      );

    // Fetch code score
    axios
      .get(`${BASE_URL}/api/code_score`)
      .then((response) => {
        const score = response.data;
        setCodeScore(score);
        setCodeScoreData({
          labels: ["Secure", "Vulnerable"],
          datasets: [
            {
              label: "Code Quality Score",
              data: [score, 100 - score],
              backgroundColor: ["#9C27B0", "#4A148C"],
              hoverOffset: 4,
            },
          ],
        });
      })
      .catch((error) => console.error("Error fetching code score:", error));

    axios
      .get(`${BASE_URL}/api/vulnerabilities/severity`)
      .then((response) => {
        const labels = Object.keys(response.data);
        const backgroundColors = labels.map(
          (_, index) => colorPalette[index % colorPalette.length]
        );

        setBarData({
          labels,
          datasets: [
            {
              label: "Severity of Vulnerabilities",
              data: labels.map((label) => response.data[label]), // Use the severity value directly from the response
              backgroundColor: backgroundColors,
            },
          ],
        });
      })
      .catch((error) => console.error("Error fetching severity data:", error));

      axios
      .get(`${BASE_URL}/api/donought_chart`)
      .then((response) => {
        const labels = Object.keys(response.data);
        const data = Object.values(response.data);
        console.log(data);
        
        const backgroundColors = labels.map(
          (_, index) => colorPalette2[index % colorPalette2.length]
        );

        setPieData({
          labels,
          datasets: [
            {
              label: "Severity of Vulnerabilities",
              data,
              backgroundColor: backgroundColors,
              hoverOffset: 4,
            },
          ],
        });
      })
      .catch((error) => console.error("Error fetching severity data:", error));
      

    // Fetch timeline data
    axios
      .get(`${BASE_URL}/api/vulnerabilities/timeline`)
      .then((response) => {
        setLineData({
          labels: Array.from({ length: response.data.length }, (_, i) => i + 1),
          datasets: [
            {
              label: "Vulnerabilities Over Time",
              data: response.data.map((entry) => entry[1]),
              fill: false,
              borderColor: "#BA68C8",
              tension: 0.1,
            },
          ],
        });
        setLoading(false);
      })
      .catch((error) => console.error("Error fetching timeline data:", error));
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');  // Redirect to login if no token is found
    } else {
      fetchData();  // Only call fetchData if the token exists
    }
  }, [totalApis, totalVulnerabilities, codeScore, pieData]);

  if (loading) {
    return <LoadingComponent />;
  }

  return (
    <Box
      sx={{
        backgroundImage: "url(/all_background.png)",
        backgroundSize: "cover",
        backgroundPosition: "center",
        backgroundAttachment: "fixed",
        minHeight: "100vh",
        minWidth: "100vw",
        padding: "2rem 0",
        overflowX: "hidden",
        overflowY: "hidden",
      }}
    >
      <Container maxWidth="lg" sx={{ position: "relative", zIndex: 2 }}>
        <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
        <div className="row">
            <div className="col-12">
              <div className="row">
                <div className="col-6">
                  <Paper
                    sx={{
                      padding: "1rem",
                      textAlign: "center",
                      backgroundColor: "rgba(33, 33, 62, 0.8)",
                      height: "153px",
                      marginBottom: "10px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center"
                    }}
                  >
                    <Typography variant="h6" sx={{ color: "#fff" }}>
                      Total APIs: {totalApis}
                    </Typography>
                  </Paper>
                </div>
                <div className="col-6">
                  <Link to="/apis">
                    <Paper
                      sx={{
                        padding: "1rem",
                        textAlign: "center",
                        backgroundColor: "rgba(33, 33, 62, 0.8)",
                        height: "153px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center"
                      }}
                    >
                      <Typography variant="h6" sx={{ color: "#fff" }}>
                        Show all APIs
                      </Typography>
                    </Paper>
                  </Link>
                </div>
              </div>
              <div className="row">
                <div className="col-6">
                  <Paper
                    sx={{
                      padding: "1rem",
                      textAlign: "center",
                      backgroundColor: "rgba(33, 33, 62, 0.8)",
                      height: "153px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center"
                    }}
                  >
                    <Typography variant="h6" sx={{ color: "#fff" }}>
                      Total Vulnerabilities: {totalVulnerabilities}
                    </Typography>
                  </Paper>
                </div>
                <div className="col-6">
                  <Link to="/vulnerabilities">
                    <Paper
                      sx={{
                        padding: "1rem",
                        textAlign: "center",
                        backgroundColor: "rgba(33, 33, 62, 0.8)",
                        height: "153px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center"
                      }}
                    >
                      <Typography variant="h6" sx={{ color: "#fff" }}>
                        Show all Vulnerabilties
                      </Typography>
                    </Paper>
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </Grid>
          
          <Grid item xs={12} md={3}>
            <Paper
              sx={{
                padding: "1rem",
                textAlign: "center",
                backgroundColor: "rgba(33, 33, 62, 0.8)",
              }}
            >
              <Pie
                data={codeScoreData}
                options={{
                  responsive: true,
                  plugins: {
                    legend: {
                      display: false, // This will hide the legend
                    },
                  },
                }}
              />
              <Typography
                variant="h6"
                sx={{ color: "#fff", marginTop: "1rem" }}
              >
                Security Score: {codeScore}/100
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={3}>
            <Paper
              sx={{
                padding: "1rem",
                textAlign: "center",
                backgroundColor: "rgba(33, 33, 62, 0.8)",
              }}
            >
              <Doughnut
                data={pieData}
                options={{
                  responsive: true,
                  plugins: {
                    legend: {
                      display: false, // This will hide the legend
                    },
                  },
                }}
              />
              <Typography
                variant="h6"
                sx={{ color: "#fff", marginTop: "1rem" }}
              >
                Vulnerability Types
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                padding: "1rem",
                textAlign: "center",
                backgroundColor: "rgba(33, 33, 62, 0.8)",
              }}
            >
              <Line data={lineData} />
              <Typography
                variant="h6"
                sx={{ color: "#fff", marginTop: "1rem" }}
              >
                Vulnerabilities Over Time
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper
              sx={{
                padding: "1rem",
                textAlign: "center",
                backgroundColor: "rgba(33, 33, 62, 0.8)",
              }}
            >
              <Bar
                data={barData}
                options={{
                  responsive: true,
                  plugins: {
                    legend: {
                      display: false, // Hide the legend
                    },
                  },
                  scales: {
                    x: {
                      ticks: {
                        display: false, // Hide the X-axis labels
                      },
                      title: {
                        display: false, // Hide the X-axis title
                      },
                    },
                    y: {
                      title: {
                        display: false, // Hide the Y-axis title
                      },
                    },
                  },
                }}
              />
              <Typography
                variant="h6"
                sx={{ color: "#fff", marginTop: "1rem" }}
              >
                Severity of Vulnerabilities
              </Typography>
            </Paper>
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
}

export default Dashboard;
