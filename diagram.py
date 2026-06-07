from diagrams import Cluster, Diagram, Edge
from diagrams.aws.analytics import Athena
from diagrams.aws.storage import S3
from diagrams.onprem.client import Client
from diagrams.programming.language import Python

with Diagram(
    "CloudTrail Investigation Quiz",
    filename="assets/architecture",
    outformat="png",
    direction="LR",
    show=False,
):
    browser = Client("Browser\n:3000")

    with Cluster("Docker Compose"):
        app = Python("Quiz App\n(Flask)")
        trino = Athena("Trino\n(Athena SQL)")
        minio = S3("MinIO\n(S3)")

        app >> Edge(label="SQL") >> trino
        trino >> Edge(label="s3a://") >> minio

    browser >> Edge(label="HTTP") >> app
