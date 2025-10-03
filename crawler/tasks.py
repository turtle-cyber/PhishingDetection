from celery import Celery
app = Celery('crawler', broker='redis://localhost:6379/0', backend='redis://localhost:6379/1')

@app.task
def crawl_url_task(url, params):
    # import local run wrapper
    from crawler.crawler_main import crawl_single_url
    return crawl_single_url(url, **params)
